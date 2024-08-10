import DBLocal from 'db-local'
import crypto from 'node:crypto'
import bcrypt from 'bcrypt'
import { SALT_ROUNDS } from './config.js';

const { Schema } = new DBLocal({ path: './db' });

const User = Schema('User', {
	_id: { type: String, required: true },
	username: { type: String, required: true },
	password: { type: String, required: true }
})

export class UserRepository {
	static async create({ username, password }) {
		// 1. Validate credentials
		Validation.username(username)
		Validation.password(password)

		const user = User.findOne({ username })
		if (user) throw new Error('username already exists')

		const id = crypto.randomUUID()
		const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS)

		User.create({
			_id: id,
			username,
			password: hashedPassword
		}).save()

		return id
	}
	static async login({ username, password }) {
		Validation.username(username)
		Validation.password(password)

		const user = User.findOne({username})
		if (!user) throw new Error("username doesn't exists")

		const isValid = await bcrypt.compare(password, user.password)
		if (!isValid) throw new Error('wrong password')

		return user.username
	}
}
class Validation {
	static username(username) {
		if (typeof username !== 'string') throw new Error('username must be a string')
		if (username.length < 4) throw new Error('username bust be at least 4 characters long')
	}

	static password(password) {
		if (typeof password !== 'string') throw new Error('password must be a string')
		if (password.length < 6) throw new Error('password bust be at least 6 characters long')
	}
}