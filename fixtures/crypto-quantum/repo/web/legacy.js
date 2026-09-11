// node:crypto calls whose verdicts differ. Not a real service.
const crypto = require("node:crypto");

const md5 = crypto.createHash("md5").update("x").digest("hex");
const sha1 = crypto.createHash("sha1").update("x").digest("hex");
const { publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 1024 });

module.exports = { md5, sha1, publicKey };
