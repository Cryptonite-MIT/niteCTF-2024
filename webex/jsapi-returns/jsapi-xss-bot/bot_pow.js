const puppeteer = require("puppeteer");
const net = require("net");
const ProofOfWork = require("./pow");
const FLAG = process.env.FLAG || "nite{inferring_cross_site_state_is_neat@23de0da8}";
const BOT_TIMEOUT = process.env.BOT_TIMEOUT || 10 * 60 * 1000;
const challengeUrl = process.env.CHALLENGE_URL || "https://chall1.nitectf.com";
const DEBUG = process.env.DEBUG || false;
const ALLOWED_SUBDOMAINS = process.env.ALLOWED_SUBDOMAINS
        ? process.env.ALLOWED_SUBDOMAINS.split(",").map((s) => s.trim())
        : [];
const PORT = process.argv[2];
const POW_DIFFICULTY = process.env.POW_DIFFICULTY || 5;
const POW_TIMEOUT = process.env.POW_TIMEOUT || 30000;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function dec2hex (dec) {
  return dec.toString(16).padStart(2, "0")
}

function generateId (len) {
  var arr = new Uint8Array((len || 40) / 2)
  crypto.getRandomValues(arr)
  return Array.from(arr, dec2hex).join('')
}

const validateUrl = (inputUrl) => {
  try {
    const parsedUrl = new URL(inputUrl);

    if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
      return false;
    }

    if ( DEBUG ) {
      return true;
    }

    if ( ALLOWED_SUBDOMAINS.indexOf( parsedUrl.hostname ) !== -1 ) {
      return true;
    }

    return false;
  } catch (error) {
    return false;
  }
};

if (!PORT) {
  console.log("Listening port not provided");
  process.exit();
}
(async function () {
  const browser = await puppeteer.launch({
    headless: "new",
    dumpio: true,
    args: [
      "--no-sandbox",
      "--disable-extensions",
      "--disable-background-networking",
      "--disable-dev-shm-usage",
      "--disable-default-apps",
      "--disable-gpu",
      "--disable-sync",
      "--disable-translate",
      "--mute-audio",
      "--no-first-run",
      "--safebrowsing-disable-auto-update",
      "--js-flags=--noexpose_wasm,--jitless",
    ],
    ignoreHTTPSErrors: true,
  });
  async function load_url(socket, data) {
    let url = data.toString().trim();
    if (url === "testing") return;
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      socket.state = "ERROR";
      socket.write("Invalid scheme (http/https only).");
      socket.destroy();
      return;
    }
    socket.state = "LOADED";
    const context = await browser.createBrowserContext();
    const page = await context.newPage();
    page.on("dialog", async (dialog) => await dialog.dismiss());
    console.log(`Loading page ${url}`);

    try {

      if (!validateUrl(url)) {
        console.log(`Invalid URL: ${url}`);
        socket.write("Invalid URL");
        socket.destroy();
        return;
      }

      await page.goto(challengeUrl, {
        waitUntil: "networkidle2",
      });
      console.log(`Page loaded: ${challengeUrl}`);
      const password = generateId(16);
      console.log(`Password`, password);
      for (let i = 0; i < password.length; i++) {
          const buttonId = `#press-${password[i]}`;
          try {
              await page.waitForSelector(buttonId, { visible: true });
              await page.click(buttonId);
          } catch (error) {
              console.error(`Error clicking button with ID: ${buttonId}`, error);
          }
      }
      console.log("URL: ", page.url());
      await page.waitForSelector('#save-new-secret', { visible: true });
      await page.click('#save-new-secret');
      await page.waitForSelector('#vault-text-area', { visible: true });
      await page.focus('#vault-text-area');
      await page.type('#vault-text-area', FLAG);
      await page.waitForSelector('#vault-submit', { visible: true });
      await page.click('#vault-submit');

      await sleep(1000);

      await page.goto(url, {
        waitUntil: "networkidle2",
      });

      console.log(`Page loaded: ${url}`);
      socket.write("Page loaded");
    } catch (err) {
      console.log(`Error: ${err}`);
      socket.write("Error occurred while processing request");
    }

    setTimeout(() => {
      try {
        context.close();
        socket.destroy();
      } catch (err) {
        console.log(`err: ${err}`);
      }
    }, BOT_TIMEOUT);
  }

  const pow = new ProofOfWork(POW_DIFFICULTY, POW_TIMEOUT);
  const server = net.createServer(async (socket) => {
    try {
      if ( DEBUG ) {
        console.log("DEBUG: Skipping PoW verification");
      } else {
        await pow.handlePowVerification(socket);
      }

      // After PoW verification, handle URL submissions
      socket.on("data", (data) => {
        try {
          load_url(socket, data);
        } catch (err) {
          console.log(`Error: ${err}`);
          socket.write("Error processing URL request\n");
          socket.destroy();
        }
      });
    } catch (err) {
      console.log(`PoW Error: ${err}`);
      socket.destroy();
    }
  });

  server.listen(PORT);
  console.log(
    `Listening on port ${PORT} with PoW difficulty ${POW_DIFFICULTY}`
  );
})();
