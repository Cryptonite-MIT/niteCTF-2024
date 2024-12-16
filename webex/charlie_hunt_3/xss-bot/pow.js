const crypto = require("crypto");

class ProofOfWork {
  constructor(difficulty = 5, timeout = 30000) {
    this.difficulty = difficulty;
    this.timeout = timeout;
  }

  generateChallenge(length = 32) {
    return crypto.randomBytes(length).toString("hex");
  }

  verifyProofOfWork(challenge, nonce) {
    const hash = crypto
      .createHash("sha256")
      .update(challenge + nonce)
      .digest("hex");
    return hash.startsWith("0".repeat(this.difficulty));
  }

  async handlePowVerification(socket) {
    return new Promise((resolve, reject) => {
      const challenge = this.generateChallenge();
      let powVerified = false;

      socket.write(
        `Proof of work enabled. Please solve the challenge using the given script and enter solution to continue.\nChallenge:\`node pow_sol.js ${challenge} ${this.difficulty}\`\n`
      );

      const timeoutId = setTimeout(() => {
        if (!powVerified) {
          socket.write("Proof of work timeout exceeded.\n");
          reject(new Error("PoW timeout"));
        }
      }, this.timeout);

      const handleData = (data) => {
        const nonce = data.toString().trim();

        if (this.verifyProofOfWork(challenge, nonce)) {
          powVerified = true;
          clearTimeout(timeoutId);
          socket.removeListener("data", handleData);
          socket.write("Proof of work verified. Please submit your URL:\n");
          resolve();
        } else {
          socket.write("Invalid proof of work. Try again:\n");
        }
      };

      socket.on("data", handleData);
    });
  }
}

module.exports = ProofOfWork;
