'use strict';

// Frida 16 plain script: use its built-in global Java bridge.
// No imports, bundle container, hooks, Activity creation, or method replacement.
var decoderClass16 = null;
var decoder16 = null;
var loader16 = null;
var pollTimer16 = null;
var pollState16 = null;

function prepare16() {
  if (decoder16 !== null) return { ready: true, loader: loader16 };
  if (typeof Java === 'undefined' || !Java.available) {
    throw new Error('Built-in Java bridge is unavailable');
  }
  var failures = [];
  Java.performNow(function () {
    function select(factory, description) {
      try {
        var cls = factory.use('ppaishc.ishc.moc.nc.StubApp');
        decoder16 = cls.getString2.overload('int');
        decoderClass16 = cls;
        loader16 = description;
        return true;
      } catch (error) {
        failures.push(description + ': ' + error);
        return false;
      }
    }
    if (select(Java.classFactory, 'default factory')) return;
    var loaders = Java.enumerateClassLoadersSync();
    for (var i = 0; i < loaders.length; i++) {
      var loader = loaders[i];
      if (select(Java.ClassFactory.get(loader), loader.toString())) return;
    }
  });
  if (decoder16 === null) throw new Error('StubApp unresolved: ' + failures.join('\n'));
  return { ready: true, loader: loader16, failedCandidates: failures.length };
}

function stop16(reason) {
  if (pollTimer16 !== null) clearInterval(pollTimer16);
  pollTimer16 = null;
  if (pollState16 !== null && pollState16.running) {
    pollState16.running = false;
    pollState16.reason = reason || 'stopped';
    pollState16.elapsedMs = Date.now() - pollState16.started;
    send(Object.assign({ event: 'poll-done' }, pollState16));
  }
  return pollState16;
}

function startPoll16(ids, timeoutMs, intervalMs) {
  if (pollTimer16 !== null) throw new Error('A poll is already active');
  timeoutMs = timeoutMs || 15000;
  intervalMs = intervalMs || 25;
  if (!Array.isArray(ids) || ids.length < 1 || ids.length > 1000 ||
      ids.some(function (id) { return typeof id !== 'number' || id !== Math.floor(id) || id < 0 || id > 2147483647; }) ||
      timeoutMs < 1 || timeoutMs > 15000 || intervalMs < 25 || intervalMs > 50) {
    throw new Error('Use 1..1000 IDs, 1..15000 ms timeout and 25..50 ms interval');
  }
  var pending = ids.slice();
  var next = 0;
  pollState16 = { running: true, pending: pending.length, attempts: 0,
    started: Date.now(), elapsedMs: 0, errors: {} };
  pollTimer16 = setInterval(function () {
    var state = pollState16;
    state.elapsedMs = Date.now() - state.started;
    if (state.elapsedMs >= timeoutMs) { stop16('timeout'); return; }
    state.attempts++;
    var rows = [];
    try {
      prepare16();
      state.loader = loader16;
      delete state.errors.prepare;
      Java.performNow(function () {
        while (next < pending.length) {
          var id = pending[next];
          try {
            var value = decoder16.call(decoderClass16, id);
            if (value === null) { state.errors[String(id)] = 'decoder returned null'; break; }
            rows.push({ id: id, value: value.toString() });
            delete state.errors[String(id)];
            next++;
            state.pending = pending.length - next;
            if (rows.length >= 16) {
              send({ event: 'constant-strings', rows: rows.splice(0), elapsedMs: Date.now() - state.started });
            }
          } catch (error) {
            state.errors[String(id)] = String(error);
            break;
          }
        }
      });
    } catch (error) { state.errors.prepare = String(error); }
    if (rows.length) send({ event: 'constant-strings', rows: rows, elapsedMs: Date.now() - state.started });
    if (state.pending === 0) stop16('all-decoded');
    else if (state.attempts === 1 || state.attempts % 20 === 0) {
      send(Object.assign({ event: 'poll-progress' }, state));
    }
  }, intervalMs);
  return { started: true, ids: pending.length, timeoutMs: timeoutMs, intervalMs: intervalMs };
}

rpc.exports = {
  info: function () {
    return {
      pid: Process.id, arch: Process.arch, frida: Frida.version,
      javaAvailable: typeof Java !== 'undefined' && Java.available,
      resolved: decoder16 !== null
    };
  },
  prepare: prepare16,
  startpoll: startPoll16,
  stop: function () { return stop16('stopped-by-rpc'); },
  progress: function () { return pollState16; },
  pollstatus: function () { return pollState16; },
  decode: function (ids) {
    if (!Array.isArray(ids) || ids.length > 1000) {
      throw new Error('Expected at most 1000 int32 constant IDs');
    }
    prepare16();
    var result = [];
    Java.performNow(function () {
      ids.forEach(function (id) {
        if (typeof id !== 'number' || id !== Math.floor(id) || id < 0 || id > 2147483647) {
          result.push({ id: id, error: 'Expected a nonnegative int32 constant ID' });
          return;
        }
        try {
          var value = decoder16.call(decoderClass16, id);
          result.push({ id: id, value: value === null ? null : value.toString() });
        } catch (error) {
          result.push({ id: id, error: String(error) });
        }
      });
    });
    return result;
  }
};
