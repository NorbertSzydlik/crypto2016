var express = require("express");
var cookieParser = require('cookie-parser')
var Mustache = require("mustache");
var sha256 = require("sha256");

module.exports = function(db) {
  var user = express();
  user.use(cookieParser());

  var bodyParser = require('body-parser')
  user.use( bodyParser.json() );       // to support JSON-encoded bodies
  user.use(bodyParser.urlencoded({     // to support URL-encoded bodies
    extended: true
  }));

  user.get("/", function(req, res) {
    var sessionId = req.cookies.sessionId;
    db.get("SELECT name FROM users WHERE sessionId=$sessionId", {$sessionId: sessionId}, function(err, row) {
      if(row == undefined) {console.log("user not logged"); res.redirect("/login"); return;}

      var template = '<html>' +
      '{{error}}' +
      '<a href="/user/">Lista przelewów</a>' +
      '<a href="/user/przelew">Nowy przelew</a>' +
      '<table><thead><tr><th>tytuł</th><th>nr konta</th><th>kwota</th></tr></thead><tbody>{{#przelewy}}<tr><td>{{title}}</td><td>{{targetAccount}}</td><td>{{amount}}</td></tr>{{/przelewy}}</tbody></table>' +
      '</html>';

      view = {przelewy: []};
      db.all("SELECT userName, title, targetAccount, amount FROM payments WHERE userName=$userName", {$userName: row.name}, function(err, rows) {
        view.przelewy = rows || [];
        res.send(Mustache.render(template, view));
      });
    });
  });


  var przelewTemplate = '<html>' +
  '{{error}}' +
  '<a href="/user/">Lista przelewów</a>' +
  '<a href="/user/przelew">Nowy przelew</a>' +
  '<form method="post"><input type="text" name="title" placeholder="Tytuł"/><input type="text" name="targetAccount" placeholder="Nr konta"/><input type="text" name="amount" placeholder="Kwota"/><button name="submit">Zrób przelew</button></form>' +
  '</html>';
  user.get("/przelew", function(req, res) {
    var sessionId = req.cookies.sessionId;
    db.get("SELECT name FROM users WHERE sessionId=$sessionId", {$sessionId: sessionId}, function(err, row) {
      if(row == undefined) {console.log("user not logged"); res.redirect("/login"); return;}

      res.send(Mustache.render(przelewTemplate, {}));
    });
  });

  user.post("/przelew", function(req, res) {
    var sessionId = req.cookies.sessionId;
    db.get("SELECT name FROM users WHERE sessionId=$sessionId", {$sessionId: sessionId}, function(err, row) {
      if(row == undefined) {console.log("user not logged"); res.redirect("/login"); return;}
      var title = req.body.title;
      var targetAccount = req.body.targetAccount;
      var amount = req.body.amount;

      db.run("INSERT INTO payments (userName, title, targetAccount, amount) VALUES(?, ?, ?, ?)", row.name, title, targetAccount, amount, function(err) {
        res.redirect("/user");
      });
    });
  });

  return user;
}
