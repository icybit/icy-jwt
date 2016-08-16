var test = require('tape'),
    icyJWT = require('../lib/auth.js');

test('Should unauthorize when user is not found', function (t) {
    var req = { },
        res = { };

    icyJWT()(req, res, function (err) {
        t.true(err, 'Should exist');
        t.equal(err.message, 'Unauthorized', 'Should match');
        t.end();
    });
});

test('Should unauthorize when user scopes are undefined', function (t) {
    var req = { user: { } },
        res = { };

    icyJWT()(req, res, function (err) {
        t.true(err, 'Should exist');
        t.equal(err.message, 'Unauthorized', 'Should match');
        t.end();
    });
});

test('Should unauthorize when expected scopes are undefined', function (t) {
    var req = { user: { scopes: ['user:read'] } },
        res = {};

    icyJWT()(req, res, function (err) {
        t.true(err, 'Should exist');
        t.equal(err.message, 'Unauthorized', 'Should match');
        t.end();
    });
});

test('Should unauthorize when expected scope is not found', function (t) {
    var req = { user: { scopes: ['user:read'] } },
        res = { };

    icyJWT(['user:write'])(req, res, function (err) {
        t.true(err, 'Should exist');
        t.equal(err.message, 'Unauthorized', 'Should match');
        t.end();
    });
});

test('Should unauthorize when none of the expected scopes are found', function (t) {
    var req = { user: { scopes: ['user:read'] } },
        res = { };

    icyJWT(['user:write', 'user:manage'])(req, res, function (err) {
        t.true(err, 'Should exist');
        t.equal(err.message, 'Unauthorized', 'Should match');
        t.end();
    });
});

test('Should authorize when expected scope is found', function (t) {
    var req = { user: { scopes: ['user:read'] } },
        res = {};

    icyJWT(['user:read'])(req, res, function (err) {
        t.error(err, 'Should not exist');
        t.end();
    });
});

test('Should authorize when any of the expected scopes are found', function (t) {
    var req = { user: { scopes: ['user:read'] } },
        res = {};

    icyJWT(['user:read', 'user:write'])(req, res, function (err) {
        t.error(err, 'Should not exist');
        t.end();
    });
});


