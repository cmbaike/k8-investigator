class RecorderProcessor extends AudioWorkletProcessor {
  process(inputs) {
    const channel = inputs[0] && inputs[0][0];

    if (channel && channel.length > 0) {
      this.port.postMessage(channel.slice(0));
    }

    return true;
  }
}

registerProcessor("investigation-recorder", RecorderProcessor);
