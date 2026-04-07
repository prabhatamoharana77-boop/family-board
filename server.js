import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import postgres from 'postgres'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

const JWT_SECRET = 'family-board-secret-change-this-in-production'
const PORT = process.env.PORT || 3000

const sql = postgres(process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost/familyboard')

const app = new Hono()

app.use('*', cors())

async function requireAuth(c, next) {
  const authHeader = c.req.header('Authorization')
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ error: 'Unauthorised' }, 401)
  }
  const token = authHeader.slice(7)
  try {
    const decoded = jwt.verify(token, JWT_SECRET)
    c.set('user', decoded)
  } catch {
    return c.json({ error: 'Unauthorised' }, 401)
  }
  await next()
}

app.get('/', (c) => {
  return c.json({ message: 'Family Board API is running' })
})

app.get('/api/messages', async (c) => {
  try {
    const messages = await sql`SELECT * FROM messages ORDER BY created_at DESC`
    return c.json(messages)
  } catch (err) {
    return c.json({ error: 'Failed to fetch messages' }, 500)
  }
})

app.post('/api/messages', requireAuth, async (c) => {
  const { name, text } = await c.req.json()
  try {
    const [message] = await sql`INSERT INTO messages (name, text) VALUES (${name}, ${text}) RETURNING *`
    return c.json(message, 201)
  } catch (err) {
    return c.json({ error: 'Failed to save message' }, 500)
  }
})

app.post('/api/register', async (c) => {
  const { email, password } = await c.req.json()
  const hashed = await bcrypt.hash(password, 10)
  try {
    await sql`INSERT INTO users (email, password_hash) VALUES (${email}, ${hashed})`
    return c.json({ message: 'User created' }, 201)
  } catch (err) {
    if (err.code === '23505') {
      return c.json({ error: 'Email already registered' }, 409)
    }
    return c.json({ error: 'Failed to create user' }, 500)
  }
})

app.post('/api/login', async (c) => {
  const { email, password } = await c.req.json()
  const [user] = await sql`SELECT * FROM users WHERE email = ${email}`
  if (!user) {
    return c.json({ error: 'Invalid credentials' }, 401)
  }
  const valid = await bcrypt.compare(password, user.password_hash)
  if (!valid) {
    return c.json({ error: 'Invalid credentials' }, 401)
  }
  const token = jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' })
  return c.json({ token })
})

async function seed() {
  const [existing] = await sql`SELECT id FROM users LIMIT 1`
  if (!existing) {
    const hashed = await bcrypt.hash('letmein123', 10)
    await sql`INSERT INTO users (email, password_hash) VALUES ('family@home.com', ${hashed})`
    console.log('Seed user created: family@home.com / letmein123')
  }
}

async function start() {
  try {
    await sql`SELECT 1`
    console.log('Database connected')
  } catch (err) {
    console.error('Database connection failed:', err)
    process.exit(1)
  }

  await sql`CREATE TABLE IF NOT EXISTS messages (id SERIAL PRIMARY KEY, name TEXT NOT NULL, text TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW())`
  await sql`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW())`
  console.log('Tables ready')

  await seed()

  serve({ fetch: app.fetch, port: PORT }, () => {
    console.log(`Server running at http://localhost:${PORT}`)
  })
}

start()
