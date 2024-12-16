const puppeteer = require("puppeteer");
const net = require("net");
const ProofOfWork = require("./pow");

const BOT_TIMEOUT = process.env.BOT_TIMEOUT || 15 * 1000;
const charlieUrl =
  process.env.CHARLIE_URL || "https://charlie-verzz1on-3.chalz.nitectf2024.live";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "adminz";
const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD || "ajdlaeahardadminpassword0987afjafh";
const PORT = process.argv[2];
const POW_DIFFICULTY = process.env.POW_DIFFICULTY || 5;
const POW_TIMEOUT = process.env.POW_TIMEOUT || 30000;
const CHALLENGE = process.env.CHALLENGE || "CHARLIE"
//const ALLOWED_SUBDOMAINS = process.env.ALLOWED_SUBDOMAINS || "charlie-verzz1on-3.chalz"

if (!PORT) {
  console.log("Listening port not provided");
  process.exit();
}
(async function () {
  const browser = await puppeteer.launch({
    headless: "new",
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


      const ALLOWED_SUBDOMAINS = process.env.ALLOWED_SUBDOMAINS
        ? process.env.ALLOWED_SUBDOMAINS.split(",").map((s) => s.trim())
        : [];

      const validateUrl = (inputUrl) => {
          const parsedUrl = new URL(inputUrl);

          const hostnameParts = parsedUrl.hostname.split(".");
          if (hostnameParts.length < 3) {
            console.log("Length not enough");
            return false;
          }

          const subdomain = hostnameParts[0];
          if (!ALLOWED_SUBDOMAINS.includes(subdomain)) {
            console.log("Invalid Subdomain"); 
            print(subdomain);
            return false;
          }

          const domain = hostnameParts.slice(1).join(".");
          if (domain !== "chalz.nitectf2024.live") {
            console.log("Invalid Domain");
            return false;
          }

          //Remove suspicious characters
          if (/[<@>]/.test(parsedUrl.pathname)) {
            console.log("Invalid chars in url");
            return false;
          }

          return true;
      };

        if (!validateUrl(url)) {
        socket.write("Invalid URL");
        socket.destroy();
        return;
       }

      if (CHALLENGE == 'CHARLIE') {
        await page.goto(charlieUrl);
        const cookies = await page.cookies();
        const phpSessionCookie = cookies.find(
          (cookie) => cookie.name === "PHPSESSID"
        );
        if (!phpSessionCookie) {
          socket.write("Failed to get PHP session");
          console.log("Failed to get PHP session");
          socket.destroy();
          return;
        } else {
          console.log(phpSessionCookie.value);
        }

        const loginResponse = await page.evaluate(
          async (charlieUrl, sessionId, ADMIN_USERNAME, ADMIN_PASSWORD) => {
            const response = await fetch(`${charlieUrl}?route=login`, {
              method: "POST",
              headers: {
                Cookie: `PHPSESSID=${sessionId}`,
                "Content-Type": "application/x-www-form-urlencoded",
              },
              body: `username=${ADMIN_USERNAME}&password=${ADMIN_PASSWORD}`,
            });
            return response.ok;
          },
          charlieUrl,
          phpSessionCookie.value,
          ADMIN_USERNAME,
          ADMIN_PASSWORD
        );

        if (!loginResponse) {
          socket.write("Admin failed");
          console.log("Admin failed");
          socket.destroy();
          return;
        }

        // Visit the provided URL
        await page.goto(url);
        socket.write("admin visited");
      }  else {
	socket.write("ENV set to not visit a url");
       // await page.goto(url);
      }

    setTimeout(() => {
        context.close();
        socket.destroy();
    }, BOT_TIMEOUT);
  }

  const pow = new ProofOfWork(POW_DIFFICULTY, POW_TIMEOUT);
  const server = net.createServer(async (socket) => {
    try {
      // Verify proof of work first
      await pow.handlePowVerification(socket);

      // After PoW verification, handle URL submissions
      socket.on("data", (data) => {
          load_url(socket, data);
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
