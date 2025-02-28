// passwordWorker.js
// Import zxcvbn if necessary, for example via a CDN or bundler
import { zxcvbn } from 'https://cdn.jsdelivr.net/npm/@zxcvbn-ts/core@3.0.4/+esm';
self.addEventListener("message", (event) => {
  const { taskId,password, url } = event.data;
  const passwordStrength = zxcvbn(password);
  // Send back result along with original URL if needed
  self.postMessage({ taskId,url, passwordStrength });
});
