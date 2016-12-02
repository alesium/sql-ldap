/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 * Copyright (c) 2016, Les Technologies Alesium, Inc.
 */

var assert = require('assert');

var ldap = require('ldapjs');


///--- Globals

var parseDN = ldap.parseDN;


///--- Functions


function operationsError(err) {
    var msg = err && err.message ? err.message : '';
    return new ldap.OperationsError('SQL failure: ' + msg,
                                    null, operationsError);
}


function _error(err, req) {
    switch (err.name) {
    case 'ObjectNotFoundError':
        return new ldap.NoSuchObjectError(req ? req.dn.toString() : '');
    case 'UniqueAttributeError':
        return new ldap.ConstraintViolationError(err.message);
    case 'ConnectionClosedError':
    case 'ConnectionTimeoutError':
    case 'NoConnectionError':
        // Moray unavailable
        return new ldap.UnavailableError(err.message);
    default:
        return operationsError(err);
    }
}


function _exists(req) {
    return function exists(key, callback) {
        var client = req.sqldbpool,
            log = req.log,

        var uid = _get_dn_as_obj(parseDN(key)).uid;
        log.debug({key: key, uid: uid}, 'exists entered');
        return client.query(_get_query(req, parseDN(key)), uid, function (err, results) {
            if (err) {
                if (err.name === 'ObjectNotFoundError') {
                    return callback(null, false);
                }

                return callback(operationsError(err));
            }
            return callback(null, true);
        });
    };
}


function _get(req) {
    return function get(key, callback) {
        var client = req.sqldbpool,
            log = req.log;

        var uid = _get_dn_as_obj(parseDN(key)).uid;
        log.debug({dn: dn, key: key, uid: uid}, 'get entered');

        return client.query(_get_query(req, parseDN(key)), uid, function (err, results) {
            if (err) {
                return callback(_error(err, req));
            }
            if (results.length != 1 ){
              log.debug(search_session+' results are not 1: '+ results.length);
              return callback(_error('Results are not 1: '+ results.length, req));
            }
            var obj = {};
            obj.dn = req.key;
            obj.attributes = results[0];
            obj.attributes.objectClass = _get_objectClass(req, dn);
            log.debug({query: query, key: key, val: obj}, 'get done');
            return callback(null, obj);
        });
    };
}

/*

function _put(req) {
    return function put(bucket, key, value, meta, callback) {
        if (typeof (meta) === 'function') {
            callback = meta;
            meta = {};
        }

        var client = req.moray,
            log = req.log,
            opts = {
                match: meta.etag,
                req_id: req.req_id,
                headers: meta.headers || {}
            };

        opts.headers['x-ufds-changelog-bucket'] = req.config.changelog.bucket;

        log.debug({bucket: bucket, key: key, opts: opts}, 'put entered');
        return client.putObject(bucket, key, value, opts, function (err) {
            if (err) {
                return callback(_error(err, req));
            }

            log.debug({bucket: bucket, key: key, val: value}, 'put done');
            return callback(null);
        });
    };
}
*/

/*
function _del(req) {
    return function del(bucket, key, meta, callback) {
        if (typeof (meta) === 'function') {
            callback = meta;
            meta = {};
        }

        var client = req.moray,
            log = req.log,
            opts = {
                match: meta.etag,
                req_id: req.req_id,
                headers: meta.headers || {}
            };

        opts.headers['x-ufds-changelog-bucket'] = req.config.changelog.bucket;

        log.debug({bucket: bucket, key: key, opts: opts}, 'del entered');
        return client.delObject(bucket, key, opts, function (err) {
            if (err) {
                return _error(err, req);
            }

            log.debug({bucket: bucket, key: key}, 'del done');
            return callback(null);
        });
    };
}

*/
function _search(req) {
    return function search(query, filter, callback) {
        var client = req.sqldbpool,
            log = req.log;

        // Hidden control should work as expected:
        if (req.controls.some(function (c) {
            return c.type === '1.3.6.1.4.1.38678.1';
        })) {
            req.hidden = true;
        }

        if (req.sizeLimit) {
            var limit = parseInt(req.sizeLimit, 10);
            if (!isNaN(limit)) {
                opts.limit = limit;
            }
        }

        var r = client.findObjects(bucket, filter, opts);
        var results = {};

        log.debug({bucket: bucket, filter: filter}, 'search entered');

        r.once('error', function (err) {
            return callback(err);
        });

        r.on('record', function (obj) {
            if (clog) {
                /* JSSTYLED */
                var k = obj.key.replace(/^change=(\S)+/,
                    'changenumber=' + obj._id + ',');
                var value = obj.value;
                value.changenumber = obj._id;
                value.changetime = new Date(value.changetime).toISOString();
                results[k] = value;
            } else {
                results[obj.key] = obj.value;
            }
        });

        r.on('end', function () {
            log.debug({
                bucket: bucket,
                filter: filter,
                results: results
            }, 'search done');
            return callback(null, results);
        });
    };
}

/*
function _batch(req) {
    return function batch(data, meta, callback) {
        if (typeof (meta) === 'function') {
            callback = meta;
            meta = {};
        }

        var client = req.moray,
            log = req.log,
            opts = {
                match: meta.etag,
                req_id: req.req_id,
                headers: meta.headers || {}
            };

        opts.headers['x-ufds-changelog-bucket'] = req.config.changelog.bucket;

        log.debug({data: data, opts: opts}, 'batch entered');
        return client.batch(data, opts, function (err, m) {
            if (err) {
                return callback(_error(err, req));
            }

            log.debug({data: data, meta: m}, 'batch done');
            return callback(null, m);
        });
    };
}
*/

function _get_dn_as_obj(dn){
  var arr = dn.split("\,\ ");
  var ret = new Object();
  arr.forEach(function(entry) {
    a = entry.split("=");
    if (ret[a[0]])
    ret[a[0]].push(a[1]);
    else
    ret[a[0]] = [a[1]];
  });
  return ret;
}

function _get_query(req, dn){
  if (dn.childOf(req.suffix)){
    return req.tree[dn].query;
  } else {
    return null;
  }
}

function _get_objectClass(req, dn){
  if (dn.childOf(req.suffix)){
    return req.tree[dn].objectClass;
  } else {
    return null;
  }
}

///--- Exports

module.exports = {

    operationsError: operationsError,

    setup: function commonSetup(req, res, next) {
        req.key = req.dn.toString();

        req.exists = _exists(req);
        //req.put = _put(req);
        req.get = _get(req);
        //req.del = _del(req);
        req.search = _search(req);
        //req.batch = _batch(req);
        return next();
    },

    ldapError: _error
};
