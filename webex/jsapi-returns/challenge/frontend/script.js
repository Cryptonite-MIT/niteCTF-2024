window.addEventListener("load", async () => {
    await document.requestStorageAccess();

    function NOTREACHED() {
        // destroy currently availiable data
        // Challenge Author (sohom):
        // if you are hitting this codepath repeatedly
        // please use a incognito window, your ad-blocker
        // or other extensions might be sending spurious postMessages
        // to this page
        window.location.href = `https://www.youtube.com/watch?v=FtutLA63Cp8`;
    }

    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

    const getSuffix = (full, prefix) =>
        full.startsWith(prefix) ? full.slice(prefix.length) : null;

    function dec2hex(dec) {
        return dec.toString(16).padStart(2, "0");
    }

    function generateId(len) {
        var arr = new Uint8Array((len || 40) / 2);
        window.crypto.getRandomValues(arr);
        return Array.from(arr, dec2hex).join("");
    }

    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length >= 2) return parts.slice(1,2)[0].split(";").shift();
    }

    function setCookie(name, value, days) {
        var expires = "";
        if (days) {
            var date = new Date();
            date.setTime(date.getTime() + days * 24 * 60 * 60 * 1000);
            expires = "; expires=" + date.toUTCString();
        }
        document.cookie = name + "=" + (value || "") + expires + "; path=/";
    }

    function escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    const domParser = new DOMParser();

    async function getHTML(page) {
        const resp = await fetch(`./${page}.html`);
        const htmlText = await resp.text();
        const doc = domParser.parseFromString(htmlText, "text/html");
        const wrapper = doc.querySelector("#wrapper");
        history.pushState({}, null, `./${page}.html`);
        return wrapper;
    }

    class VaultHTMLManager {
        constructor() {
            this.oldWrapper = document.querySelector("#wrapper");
        }

        async showRetrieve() {
            const wrapper = await getHTML("retrieve");
            this.oldWrapper.innerHTML = wrapper.innerHTML;
        }

        async showIndex() {
            const wrapper = await getHTML("index");
            this.oldWrapper.innerHTML = wrapper.innerHTML;
        }

        async showSetData() {
            const wrapper = await getHTML("setdata");
            this.oldWrapper.innerHTML = wrapper.innerHTML;
        }
    }

    class VaultViewManager {
        constructor() {
            const u = new URL(location.href);
            this.htmlManager = new VaultHTMLManager();
            this.loadFromPath(u.pathname);
        }

        async loadFromPath(pathName) {
            pathName = pathName || new URL(location.href).pathname;
            const vaultManager = new VaultManager();
            if (pathName === "/" || pathName === "/index.html") {
                this.htmlManager.showIndex();
                await sleep(1000);
                document
                    .querySelectorAll("button[id^='press-']")
                    .forEach((elem) => {
                        elem.addEventListener("click", (ev) => {
                            vaultManager.onUserClickBarHandler(ev.target);
                        });
                    });
                document
                    .querySelector("#save-new-secret")
                    .addEventListener("click", () => {
                        vaultManager.onClickSetData();
                    });
                document
                    .querySelector("#retrieve")
                    .addEventListener("click", () => {
                        vaultManager.onClickRetrieve();
                    });
                document
                    .querySelector("#last-passcode")
                    .addEventListener("click", () => {
                        vaultManager.showForgotKey();
                    });
                history.pushState({}.null, "/");
            } else if (pathName === "/retrieve.html") {
                this.htmlManager.showRetrieve();
                await sleep(1000);
                document
                    .querySelector("#back")
                    .addEventListener("click", (ev) => {
                        ev.preventDefault();
                        this.loadFromPath("/");
                    });
            } else if (pathName === "/setdata.html") {
                this.htmlManager.showSetData();
                await sleep(1000);
                document
                    .querySelector("#back")
                    .addEventListener("click", (ev) => {
                        ev.preventDefault();
                        this.loadFromPath("/");
                    });
                document
                    .querySelector("#vault-submit")
                    .addEventListener("click", (ev) => {
                        ev.preventDefault();
                        const val =
                            document.querySelector("#vault-text-area").value;
                        vaultManager.onSubmit(val);
                    });
            }
        }

        showRetrievedSecret(secret) {
            document.querySelector("#output").innerHTML = escapeHtml(secret);
            document.querySelector("#output").classList.remove("hidden");
            document.querySelector("#retrieve-failure").classList.add("hidden");
        }
    }

    class VaultManager {
        constructor() {
            if (VaultManager._instance) {
                return VaultManager._instance;
            }
            VaultManager._instance = this;
            this.apiKey = window.localStorage.getItem("vault-js-api-key");
            this.vaultViewManager = new VaultViewManager();
            this.currentSecretStatus = "";
            this.previousKey =
                window.localStorage.getItem("vault-previous-secret-key") || "";

            if (!this.apiKey) {
                this.apiKey = generateId(32);
                window.localStorage.setItem("vault-js-api-key", this.apiKey);
            }
        }

        async setVault(key, secret, apiKey) {
            const resp = await fetch(
                "https://vaultify-backend.chalz.nitectf2024.live/set",
                {
                    method: "POST",
                    body: new URLSearchParams({
                        status: true,
                        apiKey: apiKey || this.apiKey,
                        val: JSON.stringify(secret),
                        secret: key,
                        updateTime: Date.now(),
                    }),
                }
            );
            const r = await resp.json();
            return !r.status;
        }

        async retrieveFromVault(key) {
            const resp = await fetch(
                `https://vaultify-backend.chalz.nitectf2024.live/get?secret=${key}&apiKey=${this.apiKey}`
            );
            const r = await resp.text();
            return r;
        }

        async showVaultInformation(key) {
            const resp = await this.retrieveFromVault(key);
            this.vaultViewManager.showRetrievedSecret(resp);
        }

        getVaultApiKey() {
            return this.apiKey;
        }

        onUserClickBarHandler(elem) {
            const pressedKey = elem.dataset.val;
            this.currentSecretStatus += pressedKey;
            history.pushState(
                {},
                null,
                "?vaultData=" + this.currentSecretStatus
            );
        }

        async onClickRetrieve() {
            this.vaultViewManager.loadFromPath("/retrieve.html");
            await this.showVaultInformation(this.currentSecretStatus);
        }

        onClickSetData() {
            this.vaultViewManager.loadFromPath("/setdata.html");
        }

        async onSubmit(value) {
            await this.setVault(this.currentSecretStatus, value);
            this.vaultViewManager.loadFromPath("/");
            this.previousKey = this.currentSecretStatus;
            window.localStorage.setItem(
                "vault-previous-secret-key",
                this.previousKey
            );
            this.currentSecretStatus = "";
            location.hash = "";
        }

        async showForgotKey() {
            this.currentSecretStatus = "";
            history.pushState({}, null, "");
            let preKey = this.previousKey;
            // This allows for the forgotten key animation to continue smoothly
            // even if the user navigates away from the page in the middle of the animation
            if (getCookie("vault-showing-previous-key") === "true") {
                preKey = getSuffix(
                    preKey,
                    getCookie("vault-previous-key-shown")
                );
                this.currentSecretStatus = getCookie(
                    "vault-previous-key-shown"
                );
                history.pushState(
                    {},
                    null,
                    "?vaultData=" + this.currentSecretStatus
                );
            }
            for (let i = 0; i < preKey.length; i++) {
                document.querySelector(`#press-${preKey[i]}`).focus();
                document.querySelector(`#press-${preKey[i]}`).click();
                await sleep(1 * 1000);
                window.addEventListener( "beforeunload", () => {
                    setCookie("vault-showing-previous-key", "true", 1);
                    setCookie(
                        "vault-previous-key-shown",
                        preKey.slice(0, i),
                        1
                    );
                } );
            }
            setCookie("vault-showing-previous-key", "false", 1);
            setCookie("vault-previous-key-shown", "", 1);
        }
    }

    window.addEventListener("message", (ev) => {
        if (ev.origin !== getCookie("vault-trusted-origin")) {
            NOTREACHED();
        }

        const vm = new VaultManager();

        const data = JSON.parse(ev.data);

        const dtaction = data.action;
        if (dtaction === "GET") {
            vm.showVaultInformation(dtaction.secret);
        } else if (dtaction === "SET") {
            vm.setVault(dtaction.secret, dtaction.val);
        } else if (dtaction === "FORGOT") {
            vm.showForgotKey();
        } else if (dtaction === "APIKEY") {
            ev.source.postMessage(
                JSON.stringify({ apiKey: vm.getVaultApiKey() }),
                getCookie("vault-trusted-origin")
            );
        } else {
            NOTREACHED();
        }
    });

    if (new URL(location.href).pathname !== "/") {
        history.pushState({}, null, "/");
    }
    new VaultManager();

    window.addEventListener("popstate", (ev) => {
        new VaultManager();
    });
});
