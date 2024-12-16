const stars = document.querySelectorAll(".star");
const ratingMessage = document.getElementById("rating-message");
const searchForm = document.getElementById("search-form");
const searchInput = document.getElementById("search-input");
const productList = document.getElementById("product-list");

function displayProducts(filteredProducts) {
    productList.innerHTML = "";
    filteredProducts.forEach((product) => {
        const productDiv = document.createElement("div");
        productDiv.classList.add("product-item");

        const productImage = document.createElement("img");
        productImage.src = `/static/${product.image}`;
        productImage.alt = product.name;

        const productName = document.createElement("h3");
        productName.textContent = product.name;

        const productDescription = document.createElement("p");
        productDescription.textContent = product.description;

        const productPrice = document.createElement("p");
        productPrice.textContent = `Price: $${product.price}`;

        productDiv.appendChild(productImage);
        productDiv.appendChild(productName);
        productDiv.appendChild(productDescription);
        productDiv.appendChild(productPrice);

        productList.appendChild(productDiv);
    });
}

function initProducts() {
    fetch("/api/v2/search")
        .then((response) => response.json())
        .then((data) => {
            displayProducts(data.products);
        })
        .catch((error) => {
            console.error("Error fetching products:", error);
        });
}

document.addEventListener("DOMContentLoaded", () => {
    initProducts();

    searchForm.addEventListener("submit", (e) => {
        e.preventDefault();

        if (!searchInput.value.trim().length) {
            initProducts();
        } else {
            fetch(
                `/api/v2/search?query=${searchInput.value
                    .trim()
                    .toLowerCase()}`,
                { method: "POST" }
            )
                .then((response) => response.json())
                .then((data) => {
                    displayProducts(data.products);
                })
                .catch((error) => {
                    console.error("Error searching:", error);
                });
        }
    });

    stars.forEach((star) => {
        star.addEventListener("click", function () {
            const ratingValue = this.getAttribute("data-value");
            stars.forEach((s) => s.classList.remove("active"));
            for (let i = 0; i < ratingValue; i++) {
                stars[i].classList.add("active");
            }

            fetch("/api/v2/review", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ stars: ratingValue }),
            })
                .then((r) => r.json())
                .then((r) => {
                    ratingMessage.textContent = r.message ?? r.error;
                })
                .catch((error) => {
                    ratingMessage.textContent =
                        "Error submitting your review. Please try again.";
                    console.error("Error:", error);
                });
        });
    });
});
