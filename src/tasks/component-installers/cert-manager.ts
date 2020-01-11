/*********************************************************************
 * Copyright (c) 2020 Red Hat, Inc.
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 **********************************************************************/

import { Command } from '@oclif/command'
import * as fs from 'fs'
import * as Listr from 'listr'
import * as os from 'os'
import * as path from 'path'

import { KubeHelper, sleep } from '../../api/kube'
import { CERT_MANAGER_NAMESPACE_NAME, CHE_SECRET_NAME } from '../../constants'

const RESOURCES_FOLDER_PATH = path.resolve(__dirname, '..', '..', '..', 'resources')

export const CERT_MANAGER_CA_SECRET_NAME = 'ca'

export class CertManagerTasks {
  protected kubeHelper: KubeHelper

  constructor(flags: any) {
    this.kubeHelper = new KubeHelper(flags)
  }

  /**
   * Returns list of tasks which perform cert-manager checks and deploy and requests self-signed certificate for Che.
   */
  getTasks(flags: any, command: Command): ReadonlyArray<Listr.ListrTask> {
    return [
      {
        title: 'Check Cert Manager deployment',
        task: async (ctx: any, task: any) => {
          // Check only one CRD of cert-manager assuming that it is installed or not.
          ctx.certManagerInstalled = await this.kubeHelper.namespaceExist(CERT_MANAGER_NAMESPACE_NAME) && await this.kubeHelper.crdExist('certificates.cert-manager.io')
          if (ctx.certManagerInstalled) {
            task.title = `${task.title}...already deployed`
          } else {
            task.title = `${task.title}...not deployed`

            return new Listr([
              {
                title: 'Deploy cert-manager',
                task: async (ctx: any) => {
                  const yamlPath = path.join(flags.resources, '/cert-manager/cert-manager.yml')
                  await this.kubeHelper.applyResource(yamlPath)
                  ctx.certManagerInstalled = true
                }
              }
            ], ctx.listrOptions)
          }
        }
      },
      {
        title: 'Check Cert Manager CA certificate',
        task: async (ctx: any, task: any) => {
          if (!ctx.certManagerInstalled) {
            throw new Error('Cert manager must be installed before.')
          }
          // To be able to use self-signed sertificate it is required to provide CA private key & certificate to cert-manager
          const caSelfSignedCertSecret = await this.kubeHelper.getSecret(CERT_MANAGER_CA_SECRET_NAME, CERT_MANAGER_NAMESPACE_NAME)
          if (!caSelfSignedCertSecret) {
            // First run, generate CA self-signed certificate

            task.title = `${task.title}...generating new one`

            let selfSignedCertGenResult = false
            try {
              // Configure permissions for CA key pair generation job
              await this.kubeHelper.createServiceAccount('ca-cert-generator', CERT_MANAGER_NAMESPACE_NAME)
              await this.kubeHelper.createRoleFromFile(path.join(RESOURCES_FOLDER_PATH, 'cert-manager', 'ca-cert-generator-role.yml'), CERT_MANAGER_NAMESPACE_NAME)
              await this.kubeHelper.createRoleBindingFromFile(path.join(RESOURCES_FOLDER_PATH, 'cert-manager', 'ca-cert-generator-role-binding.yml'), CERT_MANAGER_NAMESPACE_NAME)

              // Run CA key pair generation job
              await this.kubeHelper.createJob('ca-cert-generation-job', 'mm4eche/che-cert-manager-ca-cert-generator:latest', 'ca-cert-generator', CERT_MANAGER_NAMESPACE_NAME)
              selfSignedCertGenResult = await this.kubeHelper.waitJob('ca-cert-generation-job', CERT_MANAGER_NAMESPACE_NAME)
            } finally {
              // Clean up resources
              try {
                // Do not change order of statements.
                // Despite logically it is better to remove role binding first, we should delete items here in order of their creation.
                // Such approach will resolve situation if only subset of items were created in previos run.
                await this.kubeHelper.deleteServiceAccount('ca-cert-generator', CERT_MANAGER_NAMESPACE_NAME)
                await this.kubeHelper.deleteRole('ca-cert-generator-role', CERT_MANAGER_NAMESPACE_NAME)
                await this.kubeHelper.deleteRoleBinding('ca-cert-generator-role-binding', CERT_MANAGER_NAMESPACE_NAME)

                await this.kubeHelper.deleteJob('ca-cert-generation-job', CERT_MANAGER_NAMESPACE_NAME)
              } catch {
                // Do nothing
              }
            }

            if (!selfSignedCertGenResult) {
              command.error('Failed to genarate self-signed CA certificate: generating job failed.')
            }
          } else {
            task.title = `${task.title}...already exists`
          }
        }
      },
      {
        title: 'Set up Che certificates issuer',
        task: async (_ctx: any, task: any) => {
          const cheClusterIssuerExists = await this.kubeHelper.clusterIssuerExists('che-cluster-issuer')
          if (!cheClusterIssuerExists) {
            const cheCertificateClusterIssuerTemplatePath = path.join(flags.resources, '/cert-manager/che-cluster-issuer.yml')
            await this.kubeHelper.applyResource(cheCertificateClusterIssuerTemplatePath)

            task.title = `${task.title}...done`
          } else {
            task.title = `${task.title}...already exists`
          }
        }
      },
      {
        title: 'Request self-signed certificate',
        task: async (ctx: any, task: any) => {
          if (ctx.cheCertificateExists) {
            throw new Error('Che certificate already exists.')
          }

          const certificateTemplatePath = path.join(flags.resources, '/cert-manager/che-certificate.yml')
          await this.kubeHelper.createCheClusterCertificate(certificateTemplatePath, flags.domain)

          task.title = `${task.title}...done`
        }
      },
      {
        title: 'Wait for self-signed certificate',
        task: async (_ctx: any, task: any) => {
          for (let i = 0; i < 5; i++) {
            const cheSecret = await this.kubeHelper.getSecret(CHE_SECRET_NAME, flags.chenamespace)
            if (cheSecret) {
              // Check CA cerfificate presence
              if (!(cheSecret.data && cheSecret.data['ca.crt'])) {
                throw new Error('Invalid Che secret: ca.crt is missing')
              }

              task.title = `${task.title}...ready`
              return
            }

            await sleep(3000)
          }

          command.error('Waiting for Che certificate timeout error.')
        }
      },
      {
        title: 'Add local Che CA certificate into browser',
        task: async (_ctx: any, task: any) => {
          const cheSecret = await this.kubeHelper.getSecret(CHE_SECRET_NAME, flags.chenamespace)
          if (cheSecret && cheSecret.data) {
            const cheCaCrt = new Buffer(cheSecret.data['ca.crt'], 'base64').toString('ascii')
            const cheCaPublicCertPath = path.join(os.homedir(), 'cheCA.crt')
            fs.writeFileSync(cheCaPublicCertPath, cheCaCrt)

            task.title = `❗[MANUAL ACTION REQUIRED] Please add local Che CA certificate into your browser: ${cheCaPublicCertPath}`
          } else {
            throw new Error('Failed to get Cert Manager CA secret')
          }
        }
      }
    ]
  }

}
