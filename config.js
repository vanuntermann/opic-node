module.exports = {
  // App Settings
  MONGO_URI: process.env.MONGO_URI || 'localhost',
  TOKEN_SECRET: 'holamundo',

  // OAuth 2.0
  GOOGLE_SECRET: process.env.GOOGLE_SECRET || 'yIuzTC_dPVa5JkFnxf43r8-L',
  MIBA_SECRET: '2880b1a909f944e7a6f2b253f88bd346',
  MIBA_SECRET_QA: '7bdd3a05fdb14a5c8535cc5b2580414e',
  
  MIBA_PROD: 'https://id.buenosaires.gob.ar/openid/',
  MIBA_HML: 'https://id.gcba.gob.ar/openid/',
  MIBA_QA: 'https://baid.qa.gcba.gob.ar/openid/'
};