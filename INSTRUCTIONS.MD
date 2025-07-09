Don't use Credential struct but instead the
```
/**
 * @typedef Password
 * @property {string} password
 * @property {string|null} app_id
 * @property {string} username
 * @property {string|null} description
 * @property {string|null} url
 * @property {string|null} otp
**/
```
Add update all field to update form and add form
You can add otpcode 
Correct the export functions, the service should be password.url || password.app_id
DONT CHANGE THE UI STYLE IN ANY WAY JUST RENAME LABEL IN FORMS AND ADD SOME FIELDS
