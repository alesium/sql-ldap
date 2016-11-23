/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 * Copyright (c) 2016, Les Technologies Alesium, Inc.
 */

/*
 * SQL LDAP Server
 */

var assert = require('assert');
var util = require('util');
var EventEmitter = require('events').EventEmitter;
var path = require('path');
var fs = require('fs');

var ldap = require('ldapjs');
var libuuid = require('libuuid');
function uuid() {
    return (libuuid.create());
}
var bunyan = require('bunyan');
var vasync = require('vasync');
var backoff = require('backoff');

var be = require('./index');
var sch = require('./schema');


function audit(req, res, next) {
    var attrs;

    var data = {
        clientip: req.connection.remoteAddress || 'localhost',
        latency: (new Date().getTime() - req.startTime),
        sql_ldapReq: {
            bindDN: req.connection.ldap.bindDN.toString(),
            msgid: req.id,
            request: req.type,
            requestDN: req.dn.toString(),
            status: res.status
        }
    };
    var sql_ldapReq = data.sql_ldapReq;
    switch (req.type) {
    case 'BindRequest':
        sql_ldapReq.bindType = req.authentication;
        break;
    case 'AddRequest':
        attrs = req.toObject().attributes;
        if (attrs.userpassword) {
            attrs.userpassword = ['XXXXXX'];
        }
        sql_ldapReq.entry = attrs;
        break;
    case 'SearchRequest':
        sql_ldapReq.scope = req.scope;
        sql_ldapReq.filter = req.filter.toString();
        sql_ldapReq.attributes = req.attributes;
        sql_ldapReq.sentEntries = req.sentEntries;
        break;
    default:
        break;
    }

    req.log.info(data, '%s "%s"', req.type, sql_ldapReq.requestDN);
}


function createSqlClient(options) {
    assert.ok(options);

    return mysql.createPool({
      connectionLimit: options.sql_connection.limits,
      user: options.sql_connection.username,
      password: options.sql_connection.password,
      database: options.sql_connection.database,
      port: options.sql_connection.port,
      host: options.sql_connection.host
    });
}


function createLDAPServer(options) {
    assert.ok(options);

    var _server = ldap.createServer(options);
    _server.after(audit);

    // Admin bind
    _server.bind(options.rootDN, function (req, res, next) {
        if (req.version !== 3) {
            return next(new ldap.ProtocolError(req.version + ' is not v3'));
        }

        if (req.credentials !== options.rootPassword) {
            return next(new ldap.InvalidCredentialsError(req.dn.toString()));
        }
        res.end();
        return next();
    });

    // ldapwhoami -H ldap://localhost:1389 -x -D cn=root -w secret
    // cn=root
    _server.exop('1.3.6.1.4.1.4203.1.11.3', function (req, res, next) {
        res.responseValue = req.connection.ldap.bindDN.toString();
        res.end();
        return next();
    });

    // RootDSE
    _server.search('', function (req, res, next) {
        function now() {
            function pad(n) {
                return String((n < 10) ? '0' + n : n);
            }
            var d = new Date();
            return String(d.getUTCFullYear() +
                pad(d.getUTCMonth() + 1) +
                pad(d.getUTCDate()) +
                pad(d.getUTCHours()) +
                pad(d.getUTCMinutes()) +
                pad(d.getUTCSeconds()) +
                '.0Z');
        }

        var entry = {
            dn: '',
            attributes: {
                namingcontexts: options.base_dn,
                supportedcontrol: [
                    '1.2.840.113556.1.4.473',   // Server side sort
                    '2.16.840.1.113730.3.4.3'   // Persistent search
                ],
                supportedextension: ['1.3.6.1.4.1.4203.1.11.3'],
                supportedldapversion: 3,
                currenttime: now(),
                objectclass: 'RootDSE'
            }
        };

        res.send(entry);
        res.end();
        return next();
    });

    _server.on('clientError', function (err) {
        // CAPI-342: Do not log.error 404s.
        if (err.name && err.name === 'NoSuchObjectError') {
            _server.log.info({err: err}, 'LDAPJS Server NoSuchObjectError');
        } else {
            _server.log.error({err: err}, 'LDAPJS Server Error');
        }
    });

    return _server;
}


function processConfigFile(file) {
    try {
        var config = JSON.parse(fs.readFileSync(file, 'utf8'));

        if (config.certificate && config.key && !config.port) {
            config.port = 636;
        }

        if (!config.port) {
            config.port = 389;
        }
    } catch (e) {
        console.error('Unable to parse configuration file: ' + e.message);
        process.exit(1);
    }
    return config;
}


function sql_ldap(config) {
    this.config = config;
    this.log = config.log;
    this.server = createLDAPServer(config);
    // This is the only tree we're interested into for sql_ldap:
    // TODO: Make this work
    this.suffix = config.base_dn;
    this.tree = config[this.suffix];
    this.use_bcrypt = (typeof (config.use_bcrypt) === 'boolean') ?
        config.use_bcrypt : true;
}

util.inherits(sql_ldap, EventEmitter);

sql_ldap.prototype.init = function (callback) {
    var self = this;
    var schema = sch.load(path.resolve(__dirname, '../schema'), self.log);
    self.log.info({schema: Object.keys(schema)}, 'Schema loaded');

    self.sqldbpool = createSqlClient(self.config);


    self.server.use(function setup(req, res, next) {
        req.req_id = uuid();
        req.log = self.log.child({req_id: req.req_id}, true);
        req.sqldb = self.sqlServer;
        req.schema = schema;
        req.config = self.config;
        // Allow to replace bcrypt encryption with SHA1 from config:
        req.use_bcrypt = self.use_bcrypt;
        return next();
    });

    var bucket = self.tree.bucket;
    var suffix = self.suffix;
    function _reqSetup(req, res, next) {
        req.bucket = bucket;
        req.suffix = suffix;
        return next();
    }

    //self.server.add(self.suffix, _reqSetup, be.add());
    self.server.bind(self.suffix, _reqSetup, be.bind());
    //self.server.compare(self.suffix, _reqSetup, be.compare());
    self.server.del(self.suffix, _reqSetup, be.del());
    //self.server.modify(self.suffix, _reqSetup, be.modify());
    self.server.search(self.suffix, _reqSetup, be.search());
    self.server.listen(self.config.port, self.config.host, callback);

    self.server.log.info('sql_ldap listening at: %s', self.server.url);
};


module.exports = {
    createServer: function createServer(options) {
        // Just create a new Bunyan instance if not given:
        if (options.log === undefined) {
            options.log = new bunyan({
                name: 'sql_ldap',
                stream: process.stdout,
                serializers: {
                    err: bunyan.stdSerializers.err
                }
            });
        }
        if (!options[options.baseDN]) {
            throw new TypeError('options[\''+options.baseDN+'\'] (Object) required');
        }

        var sql_ldap = new sql_ldap(options);
        return sql_ldap;
    },
    processConfigFile: processConfigFile
};
