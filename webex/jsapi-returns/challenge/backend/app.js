const express = require("express");
const bp = require("body-parser");

const app = express();
app.use(bp.urlencoded({ extended: true }));
app.use(bp.json());
app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", "default-src: self");
    res.setHeader(
        "Access-Control-Allow-Origin",
        "https://vaultify-frontend.chalz.nitectf2024.live"
    );
    next();
});

const PORT = 3000;

const { Sequelize, DataTypes } = require("sequelize");

const sequelize = new Sequelize("sqlite::memory");

const Data = sequelize.define("Data", {
    val: DataTypes.STRING,
    apiKey: DataTypes.STRING,
    secret: {
        type: DataTypes.STRING,
        primaryKey: true,
    },
});

Data.sync();

app.post("/set", async (req, res) => {
    const { secret, apiKey, val } = req.body;

    if (typeof secret !== "string" || secret.length < 16) {
        res.status(418);
        res.end(
            JSON.stringify({
                status: false,
            })
        );
    }

    if (typeof val !== "string") {
        res.status(418);
        res.send(
            JSON.stringify({
                status: false,
            })
        );
    }

    if (typeof apiKey !== "string" || apiKey.length < 32) {
        res.status(418);
        res.send(
            JSON.stringify({
                status: false,
            })
        );
    }

    try {
        await Data.create({
            secret,
            val,
            apiKey,
        });
    } catch (e) {
        res.status(418);
        res.end(
            JSON.stringify({
                status: false,
            })
        );
    }

    res.end(
        JSON.stringify({
            status: true,
        })
    );
});

app.get("/get", async (req, res) => {
    const { secret, apiKey } = req.query;

    if (typeof secret !== "string") {
        res.status(418);
        res.end(
            JSON.stringify({
                status: false,
            })
        );
    }

    const d = await Data.findAll({
        where: {
            secret,
            apiKey,
        },
    });

    if (d.length) {
        res.end(d[0].val);
    } else {
        res.status(418);
        res.end(
            JSON.stringify({
                status: false,
            })
        );
    }
});

app.get("/app.js", (req, res) => {
    return res.sendFile("app.js");
});

app.listen(PORT, (error) => {
    if (!error) {
        console.log(
            "Server is Successfully Running, and App is listening on port " +
                PORT
        );
    } else console.log("Error occurred, server can't start", error);
});
