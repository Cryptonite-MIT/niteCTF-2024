document.querySelector("#search").addEventListener("keyup", (e) => {
    if (!e.target?.value) {
        document
            .querySelectorAll(".product-name")
            .forEach((product) =>
                product.parentElement.parentElement.parentElement.classList.remove(
                    "hidden"
                )
            );

        return;
    }

    document
        .querySelectorAll(".product-name")
        .forEach((product) =>
            product.textContent
                .toLocaleLowerCase()
                .includes(e.target.value.toLocaleLowerCase())
                ? product.parentElement.parentElement.parentElement.classList.remove(
                      "hidden"
                  )
                : product.parentElement.parentElement.parentElement.classList.add(
                      "hidden"
                  )
        );
});

document.querySelectorAll("button[data-id]").forEach((btn) =>
    btn.addEventListener("click", async (e) => {
        e.preventDefault();

        const product_id = e.target.dataset.id;

        const qty = parseInt(prompt("Enter product quantity"));
        if (isNaN(qty) || qty < 1) {
            alert("Invalid quantity");
            return;
        }

        await fetch(`./purchase.php?id=${product_id}&qty=${qty}`, {
            method: "POST",
        })
            .then((resp) => resp.text())
            .then((resp) => alert(resp))
            .catch((err) => alert(`Error: ${err}`));
    })
);
