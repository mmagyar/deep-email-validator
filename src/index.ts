import { isEmail } from './regex/regex'
import { checkTypo } from './typo/typo'
import { getBestMx } from './dns/dns'
import { checkSMTP } from './smtp/smtp'
import { checkDisposable } from './disposable/disposable'
import { getOptions, ValidatorOptions } from './options/options'
import { OutputFormat, createOutput } from './output/output'
import './types'

export async function validate(emailOrOptions: string | ValidatorOptions): Promise<OutputFormat> {
  const options = getOptions(emailOrOptions)
  const email = options.email

  if (options.validateRegex) {
    const regexResponse = isEmail(email)
    if (regexResponse) return createOutput('regex', regexResponse)
  }

  if (options.validateTypo) {
    const typoResponse = await checkTypo(email, options.additionalTopLevelDomains)
    if (typoResponse) return createOutput('typo', typoResponse)
  }

  const domain = email.split('@')[1]

  if (options.validateDisposable) {
    const disposableResponse = await checkDisposable(domain)
    if (disposableResponse) return createOutput('disposable', disposableResponse)
  }

  if (options.validateMx) {
    const mx = await getBestMx(domain)
    if (!mx) return createOutput('mx', 'MX record not found')
    if (options.validateSMTP) {
      const ports = [25, 465, 587, 2525]
      let firstError
      for (const port of ports) {
        const result = await checkSMTP(options.sender, email, mx.exchange, port)
        if (!firstError) firstError = result
        if (result.valid) return result
      }
      return firstError as OutputFormat
    }
  }

  return createOutput()
}

export default validate
