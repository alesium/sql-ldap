var ldap = require('ldapjs'),
    bcrypt = require('bcrypt'),
    node_hash = require('node_hash'),
    PasswordHash = require('phpass').PasswordHash;

function check_password(password, hash, next){
  if (hash.substr(0,3) == '$P$'){
    // PHPPASS
    if (passwordHash.checkPassword(password, hash))
      return next(true);

    return next(ldap.InvalidCredentialsError());


  } else if (hash.substr(0,1) == '$') {
    // bcrypt
    hash = hash.replace(/^\$2y(.+)$/i, '\$2a$1');
    if (bcrypt.compare(password, hash))
      return next(true);

    return next(ldap.InvalidCredentialsError());

  } else if (hash.substr(hash, 0, 8) == '{SHA256}') {
    var parts = hash.split(':');
    var crypt = parts[0];
    var salt = parts[1];
    if (_compare_hash(password, crypt, salt, 'sha256'))
      return next(true);

    return next(ldap.InvalidCredentialsError());
  }

  return next(ldap.InvalidCredentialsError());
}

function _compare_hash(password, hash, salt, encryption, next){
  if ( encryption == 'sha256' ){
    if ( hash == node_hash.sha256(password, salt)) {
      return next(true);
    } else {
      return next(ldap.InvalidCredentialsError());
    }
  }
  return next(ldap.InvalidCredentialsError());
}

module.exports = {
    checkPassword: checkPassword
}
