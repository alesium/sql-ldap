/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2016, Les Technologies Alesium, Inc.
 */

var assert = require('assert');
var util = require('util');

var ldap = require('ldapjs');

var Validator = require('../lib/schema/validator');



///--- Globals

var LOGIN_RE = /^[a-zA-Z][a-zA-Z0-9_\.@]+$/;
var UUID_RE = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;

///--- API

// Attributes prefixed with 'pwd' come from pwdPolicy spec. See:
// http://tools.ietf.org/html/draft-behera-ldap-password-policy-10#section-5.3

function inetOrgPerson() {
    Validator.call(this, {
        name: 'inetorgperson',
        required: {
            sn: 1,
            cn: 1,
        },
        optional: {
            carlicense: 1,
            departmentnumber: 1,
            displayname: 1,
            employeenumber: 1,
            employeetype: 1,
            jpegphoto: 1,
            preferredlanguage: 1,
            usersmimecertificate: 1,
            userpks12: 1,
            audio: 1,
            businesscategory: 1,
            givenname: 1,
            homephone: 1,
            homepostaladdress: 1,
            initials: 1,
            photo: 1,
            roomnumber: 1,
            secretary: 1,
            mobile: 1,
            pager: 1,
            x500uniqueidentifier: 1
        }
    });
}
util.inherits(inetOrgPerson, Validator);




///--- Exports

module.exports = {

    createInstance: function createInstance() {
        return new inetOrgPerson();
    }

};
