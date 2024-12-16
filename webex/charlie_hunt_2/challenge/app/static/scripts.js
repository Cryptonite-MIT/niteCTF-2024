document.addEventListener("DOMContentLoaded", function () {
    const stars = document.querySelectorAll(".star");
    const ratingMessage = document.getElementById("rating-message");

    stars.forEach((star) => {
        star.addEventListener("click", function () {
            const ratingValue = this.getAttribute("data-value");
            stars.forEach((s) => s.classList.remove("active"));
            for (let i = 0; i < ratingValue; i++) {
                stars[i].classList.add("active");
            }

            fetch("/version2/user_review", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ stars: ratingValue }),
            })
                .then((response) => response.json())
                .then((data) => {
                    ratingMessage.textContent = `You rated this ${ratingValue} star(s)!`;
                })
                .catch((error) => {
                    ratingMessage.textContent =
                        "Error submitting your review. Please try again.";
                    console.error("Error:", error);
                });
        });
    });
});
