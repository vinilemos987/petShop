require("dotenv").config();
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const path = require("path");
 
const app = express();
 
app.set("trust proxy", 1);
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(cookieParser());
 
const ssl = process.env.DB_SSL_CA
    ? {
        ca: process.env.DB_SSL_CA.replace(/\\n/g, "\n"),
        rejectUnauthorized: true
    }
    : { rejectUnauthorized: true };
 
const db = new Pool({
    host: process.env.HOST,
    port: Number(process.env.DB_PORT),
    user: process.env.USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: ssl,
    max: 5
});
 
async function criarBanco() {
    await db.query(`
        CREATE TABLE IF NOT EXISTS atendimentos (
            id SERIAL PRIMARY KEY,
            tutor VARCHAR(100) NOT NULL,
            pet VARCHAR(100) NOT NULL,
            especie VARCHAR(20) NOT NULL
                CHECK (especie IN ('Cachorro', 'Gato', 'Outro')),
            servico VARCHAR(100) NOT NULL,
            valor NUMERIC(10,2) NOT NULL,
            data_atendimento DATE NOT NULL,
            criacao_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);
 
    await db.query(`
        CREATE TABLE IF NOT EXISTS usuario (
            id SERIAL PRIMARY KEY,
            email VARCHAR(70) NOT NULL UNIQUE,
            senha VARCHAR(255) NOT NULL
        )
    `);
 
    await iniciar();
}
 
async function iniciar() {
    try {
        const usuario = await db.query(
            "SELECT id FROM usuario WHERE email = $1",
            [process.env.ADMIN_EMAIL]
        );
 
        if (usuario.rows.length === 0) {
            const senhaHash = await bcrypt.hash(
                process.env.ADMIN_SENHA,
                10
            );
 
            await db.query(
                "INSERT INTO usuario (email, senha) VALUES ($1, $2)",
                [process.env.ADMIN_EMAIL, senhaHash]
            );
 
            console.log("Admin criado");
        }
    } catch (erro) {
        console.log("Não foi possível conectar com o banco de dados");
        throw erro;
    }
}
 
app.post("/api/atendimento", async (req, res) => {
    try {
        const { tutor, pet, especie, servico, valor, data } = req.body;
 
        if (!tutor || !pet || !especie || !servico || !Number(valor) || !data) {
            return res.status(400).json({ erro: "Confira todos os campos" });
        }
 
        if (valor <= 0) {
            return res.status(400).json({ erro: "valor deve ser maior que 0." });
        }
 
        const resultado = await db.query(
            `INSERT INTO atendimentos
            (tutor, pet, especie, servico, valor, data_atendimento)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id`,
            [tutor.trim(), pet.trim(), especie, servico, Number(valor), data]
        );
 
        res.status(201).json({
            mensagem: "Atendimento salvo!",
            id: resultado.rows[0].id
        });
 
    } catch (erro) {
        console.log(erro);
        res.status(500).json({ erro: "erro de conexão com o banco" });
    }
});
 
app.post("/api/login", async (req, res) => {
    try {
        const { email, senha } = req.body;
 
        if (!email || !senha) {
            return res.status(400).json({ erro: "Informe e-mail e senha!" });
        }
 
        const usuario = await db.query(
            "SELECT id, email, senha FROM usuario WHERE email = $1",
            [email.trim()]
        );
 
        if (usuario.rows.length === 0) {
            return res.status(401).json({ erro: "Credenciais incorretas." });
        }
 
        const dados = usuario.rows[0];
        const senhaCorreta = await bcrypt.compare(senha, dados.senha);
 
        if (!senhaCorreta) {
            return res.status(401).json({ erro: "Credenciais inválidas" });
        }
 
        const token = jwt.sign(
            { id: dados.id, email: dados.email },
            process.env.JWT_SEGREDO,
            { expiresIn: "1h" }
        );
 
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 60 * 60 * 1000
        });
 
        res.json({ mensagem: "Login Realizado" });
 
    } catch (erro) {
        console.log(erro);
        res.status(500).json({ erro: "Erro de conexão com o banco de dados." });
    }
});
 
function autenticar(req, res, next) {
    const token = req.cookies.token;
 
    if (!token) {
        return res.status(401).json({
            erro: "Você precisa fazer login para acessar esta página."
        });
    }
 
    try {
        req.usuario = jwt.verify(token, process.env.JWT_SEGREDO);
        next();
 
    } catch (erro) {
        res.clearCookie("token");
        res.redirect("/login.html");
        return res.status(401).json({
            erro: "Sessão inválida ou expirada."
        });
    }
}
 
app.get("/dashboard", autenticar, (req, res) => {
    res.sendFile(path.join(__dirname, "private", "dashboard.html"));
});
 
app.post("/api/logout", (req, res) => {
    res.clearCookie("token", {
        httpOnly: true,
        sameSite: "strict",
        secure: process.env.NODE_ENV === "production"
    });
 
    res.json({ mensagem: "logout efetuado" });
});
 
app.get("/api/verificar", autenticar, (req, res) => {
    res.json({ autenticado: true, usuario: req.usuario });
});
 
async function conectarPython(endpoint, atendimentos, res, tipo) {
    try {
        const url = process.env.PYTHON_API_URL;
 
        const resposta = await fetch(
            `${url.replace(/\/$/, "")}${endpoint}`,
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ atendimentos })
            }
        );
 
        if (!resposta.ok) {
            throw new Error(resposta.status);
        }
 
        const arquivo = Buffer.from(await resposta.arrayBuffer());
 
        if (tipo === "pdf") {
            res.setHeader("Content-Type", "application/pdf");
            res.setHeader(
                "Content-Disposition",
                "attachment; filename='relatorio-petshop.pdf'"
            );
        } else {
            res.setHeader("Content-Type", "image/png");
            res.setHeader(
                "Content-Disposition",
                "inline; filename=graficos.png"
            );
        }
 
        res.send(arquivo);
 
    } catch (erro) {
        console.log(erro);
        res.status(502).json({
            erro: "Não foi possivel conectar com o servidor Python"
        });
    }
}
 
app.get("/api/graficos", autenticar, async (req, res) => {
    try {
        const resultado = await db.query(`
            SELECT tutor, pet, especie, servico FROM atendimentos
        `);
 
        await conectarPython("/graficos", resultado.rows, res, "imagem");
 
    } catch (erro) {
        console.log(erro);
        res.status(500).json({
            erro: "Erro de comunicação com o Python"
        });
    }
});
 
app.get("/api/pdf", autenticar, async (req, res) => {
    try {
        const resultado = await db.query(`
            SELECT tutor, pet, especie, servico
            FROM atendimentos
            ORDER BY criacao_em
        `);
 
        await conectarPython("/pdf", resultado.rows, res, "pdf");
 
    } catch (erro) {
        console.log(erro);
        res.status(500).json({
            erro: "Erro de comunicacao com o python"
        });
    }
});
 
     const PORT = process.env.PORT || 3000
criarBanco()
    .then(() => {
   
        app.listen(process.env.PORT, "0.0.0.0", () => {
            console.log("Servidor rodando na porta " + PORT);
        });
    })
    .catch((erro) => {
        console.log(erro);
        process.exit(1);
    });
 