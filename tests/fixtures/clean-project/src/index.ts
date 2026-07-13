import express from 'express'

const app = express()
const port = Number(process.env.PORT ?? 3000)
const apiKey = process.env.API_KEY

app.get('/health', (_request, response) => {
  response.json({
    ok: true,
    hasApiKey: Boolean(apiKey),
    version: '1.2.3',
  })
})

app.listen(port, () => {
  console.log(`listening on ${port}`)
})
