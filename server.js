const express = require('express')
const port = 27017
const path = require('path')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const User = require('./model/user')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const JWT_SECRET = 'sdjkfh8923yhjdksbfma@#*(&@*!^#&@bhjb2qiuhesdbhjdsfg839ujkdhfjk'

mongoose.connect('mongodb://localhost:27017/login-app-db', {
	useNewUrlParser: true,
	useUnifiedTopology: true,
	useCreateIndex: true
})

app.listen(port, () => {
	console.log(`Example app listening on port ${27017}`)
  })
  

const app = express()
app.use('/', express.static(path.join(__dirname, 'static')))
app.use(bodyParser.json())

app.post('/api/change-password', async (req, res) => {
	const { token, newpassword: plainTextPassword } = req.body

	if (!plainTextPassword || typeof plainTextPassword !== 'string') {
		return res.json({ status: 'error', error: 'Senha invalida' })
	}

	if (plainTextPassword.length < 5) {
		return res.json({
			status: 'error',
			error: 'A senha e curta, precisa ter pelo menos 6 caracteres.'
		})
	}

	try {
		const user = jwt.verify(token, JWT_SECRET)

		const _id = user.id

		const password = await bcrypt.hash(plainTextPassword, 10)

		await User.updateOne(
			{ _id },
			{
				$set: { password }
			}
		)
		res.json({ status: 'ok' })
	} catch (error) {
		console.log(error)
		res.json({ status: 'error', error: ';))' })
	}
})

app.post('/api/login', async (req, res) => {
	const { username, password } = req.body
	const user = await User.findOne({ username }).lean()

	if (!user) {
		return res.json({ status: 'error', error: 'Usuario ou senha invalidos.' })
	}

	if (await bcrypt.compare(password, user.password)) {
		// O usuario e senha se conhecidem.

		const token = jwt.sign(
			{
				id: user._id,
				username: user.username
			},
			JWT_SECRET
		)

		return res.json({ status: 'ok', data: token })
	}

	res.json({ status: 'error', error: 'usuario ou senha invalido' })
})

app.post('/api/register', async (req, res) => {
	const { username, password: plainTextPassword } = req.body

	if (!username || typeof username !== 'string') {
		return res.json({ status: 'error', error: 'usuario invalido' })
	}

	if (!plainTextPassword || typeof plainTextPassword !== 'string') {
		return res.json({ status: 'error', error: 'senha invalida' })
	}

	if (plainTextPassword.length < 5) {
		return res.json({
			status: 'error',
			error: 'A senha e curta, precisa de pelo menos 6 caracteres.'
		})
	}

	const password = await bcrypt.hash(plainTextPassword, 10)

	try {
		const response = await User.create({
			username,
			password
		})
		console.log('Usuario criado com sucesso: ', response)
	} catch (error) {
		if (error.code === 11000) {
			// chave duplicada
			return res.json({ status: 'error', error: 'O nome de usuario ja esta em uso.' })
		}
		throw error
	}

	res.json({ status: 'ok' })
})

app.listen(27017, () => {
	console.log('Server rodando 27017')
})
