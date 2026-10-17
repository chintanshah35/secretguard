import slash from 'https://esm.sh/slash@3.0.0.js'

export const scaffold = 'npx create-vite@9.1.0 my-app'
export const remote = 'git@github.com:acme-labs/widgets.git'
export const docs = 'https://user:hunter2@api.example.com/v1'

export const bindAll = '0.0.0.0'
export const broadcast = '255.255.255.255'
export const metadata = 'http://169.254.169.254/latest/meta-data'
export const sha256WithRsa = '1.2.840.113549.1.1.11'
export const rsaOid = '1.3.6.1'
export const section = 'see RFC 7230 section 3.2.6.1'

export const fictional = { phone: '(212) 555-0147' }
export const invalidArea = { phone: '1234567890' }

export const local = 'postgres://postgres:postgres@localhost:5432/app'
export const compose = 'mysql://app:app@db:3306/app'
export const templated = 'postgres://app:${DB_PASSWORD}@db/app'

export const bundle = 'var a={label:"Contact phone",items:[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18],asset:"app.js?v=4718293056"}'

export { slash }
