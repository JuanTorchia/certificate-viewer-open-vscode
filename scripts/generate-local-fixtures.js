const fs = require("fs");
const crypto = require("crypto");

fs.mkdirSync("local", { recursive: true });

for (const alg of ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"]) {
  try {
    const { publicKey, privateKey } = crypto.generateKeyPairSync(alg);
    fs.writeFileSync(`local/${alg}.pub`, publicKey.export({ type: "spki", format: "pem" }));
    fs.writeFileSync(`local/${alg}.key`, privateKey.export({ type: "pkcs8", format: "pem" }));
    console.log(`generated ${alg} keypair`);
  } catch (error) {
    console.log(`skipped ${alg}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

const { publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
fs.writeFileSync("local/rsa-public.jwk", JSON.stringify(publicKey.export({ format: "jwk" }), null, 2));
console.log("generated local/rsa-public.jwk");
