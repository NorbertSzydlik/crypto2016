var express = require("express");
var cookieParser = require('cookie-parser')
var Mustache = require("mustache");
var sha256 = require("sha256");

module.exports = function(db) {
  var login = express();
  login.use(cookieParser());

  var bodyParser = require('body-parser')
  login.use( bodyParser.json() );       // to support JSON-encoded bodies
  login.use(bodyParser.urlencoded({     // to support URL-encoded bodies
    extended: true
  }));

  var template = '<html>' +
  '{{error}}' +
  '<form method="post">' +
  '<input type="text" name="login" placeholder="login"/><input type="password" name="password" placeholder="password"/><button name="submit">Submit</button>' +
  '</form></html>';

  login.get("/", function(req, res) {
    var view = {};
    res.send(Mustache.render(template, view));
  });

function randomString(len, charSet) {
    charSet = charSet || 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var randomString = '';
    for (var i = 0; i < len; i++) {
        var randomPoz = Math.floor(Math.random() * charSet.length);
        randomString += charSet.substring(randomPoz,randomPoz+1);
    }
    return randomString;
}
  login.post("/", function(req, res) {
    var login = req.body.login;
    var password = req.body.password;
    var view = {};

    db.get("SELECT name, salt, passwd FROM users WHERE name=$name", {$name: req.body.login}, function(err, row) {
      if(!row) {
        view.error = "Wrong username or password";
        res.send(Mustache.render(template, view));
        return;
      }

      var passwd = sha256(row.salt + password);
      if(passwd != row.passwd) {
        view.error = "Wrong username or password";
        res.send(Mustache.render(template, view));
        return;
      }

      var sessionId = randomString(256);
      db.run("UPDATE users SET sessionId=$sessionId WHERE name=$name", {$sessionId: sessionId, $name: login}, function(err) {
        res.cookie("sessionId", sessionId);
        res.redirect("/user");
      });
    });


  });

  return login;
};
