const requestOriginal = require('https').request

module.exports = function(options) {
  return new Promise((resolve, reject) => {
    const req = requestOriginal(options, response => {
      const chunks = []
      response.on('data', data => {
        chunks.push(data)
      })

      response.on('end', () => {
        resolve({ response, data: Buffer.concat(chunks) })
      })
    })
    req.on('error', reject)
    req.end()
  })
}
