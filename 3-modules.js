// Modules = Encapsulated Code (only share minimum)
// CommonJS, every file is module (by default)
// const {john, peter} = require('./4-names')  // FIRST WAY
const names = require('./4-names')  // SECOND WAY
const sayHi = require('./5-utils')
const data = require('./6-alternative-flavor')
require('./7-mind-granade')

// sayHi("susan")
// sayHi(names.peter)  // sayHi(names['peter'])
// sayHi(names.john)  // sayHi(names['john'])
// sayHi(data.singlePerson.name)

