const EventEmitter = require('events');
const frida = require('frida');
const { makeCompiler } = require('frida-compile');

class FridaClient extends EventEmitter {
  static async compile(script, cache = {}, options = {}) {
    return makeCompiler(script, cache, options)();
  }

  static async inject(device, pid, source, options) {
    const session = await device.attach(pid, options);
    return session.createScript(source);
  }

  static async getDevice(type, options) {
    if (type === 'local') return frida.getLocalDevice(options);
    if (type === 'usb') {
      return frida.getUsbDevice({ timeout: null, ...options });
    }
    throw new Error(`unknown device ${type}`);
  }

  configureEvents(script) {
    script.message.connect((message) => {
      if (message.type === 'send') {
        const { payload } = message;
        if (typeof payload === 'string') {
          this.emit('info', payload);
        } else {
          this.emit(payload.type, payload.message);
        }
      } else if (message.type === 'error') {
        this.emit('error', message.stack);
      }
    });
  }

  async connect(options = {}) {
    const {
      packageName,
      packageOptions,
      script: agentScript,
      cwd,
      realm,
    } = options;
    const { bundle: source } = await FridaClient.compile(agentScript);
    this.emit('info', 'agent built successfully');
    const device = await FridaClient.getDevice('local');
    const pid = await device.spawn(packageName, { argv: packageOptions, cwd });
    this.emit('info', `spawned ${packageName} with pid ${pid}`);
    let script = await FridaClient.inject(device, pid, source);
    this.configureEvents(script);
    await script.load();
    let done = script.exports.init(null, options);
    if (realm === 'emulated') {
      const realmScript = await FridaClient.inject(device, pid, source, {
        realm: 'emulated',
      });
      this.configureEvents(realmScript);
      await realmScript.load();
      done = done.then(() => realmScript.exports.onInit(null, options));
      script = realmScript;
    }
    this.emit('info', `${packageName} injected`);
    await device.resume(pid);
    this.emit('info', 'app execution resumed');
    done.catch((error) => this.emit('error', error));
    return script;
  }
}

module.exports = FridaClient;
