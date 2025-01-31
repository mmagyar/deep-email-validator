# Email Validator

Validates email addresses based on regex, common typos, disposable email blacklists, DNS records and SMTP server response.

- Validates email looks like an email i.e. contains an "@" and a "." to the right of it.
- Validates common typos e.g. example@gmaill.com using [mailcheck](https://github.com/mailcheck/mailcheck).
- Validates email was not generated by disposable email service using [disposable-email-domains](https://github.com/ivolo/disposable-email-domains).
- Validates MX records are present on DNS.
- Validates SMTP server is running.
- Validates mailbox exists on SMTP server.
- Native typescript support.

## Getting Started

Compatible with nodejs only. Not browser ready.

Install like so

```
npm i deep-email-validator --save
```

or with yarn

```
yarn add deep-email-validator
```

Use like so

```typescript
import { validate } from 'deep-email-validator'
const main = async () => {
  let res = await validate('asdf@gmail.com')
  // {
  //   "valid": false,
  //   "reason": "smtp",
  //   "validators": {
  //       "regex": {
  //         "valid": true
  //       },
  //       "typo": {
  //         "valid": true
  //       },
  //       "disposable": {
  //         "valid": true
  //       },
  //       "mx": {
  //         "valid": true
  //       },
  //       "smtp": {
  //         "valid": false,
  //         "reason": "Mailbox not found.",
  //       }
  //   }
  // }

  // Can also be called with these default options
  await validate({
    email: 'name@example.org',
    sender: 'name@example.org',
    validateRegex: true,
    validateMx: true,
    validateTypo: true,
    validateDisposable: true,
    validateSMTP: true,
  })
}
```

[Default options can be found here](https://github.com/mfbx9da4/deep-email-validator/blob/cefb37abc6e42d3a1551d38f9706d4ff538226e5/src/options/options.ts#L1)
