var url = 'https://www.google.com/';

function log(message) {
    // send an HTTP request
    console.log(message);
}

module.exports.log = log;
module.exports.url = url;