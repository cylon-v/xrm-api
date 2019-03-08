import Util from './util';
import Message from './message';

export class Dynamics {
  constructor(settings) {
    const util = new Util(settings);
    this.message = new Message(util);
  }

  create(options) {
    return this.message.Create(options);
  }

  update(options) {
    return this.message.Update(options);
  }

  retrieve(options) {
    return this.message.Retrieve(options);
  }

  retrieveMultiple(options) {
    return this.message.RetrieveMultiple(options);
  }

  associate(options) {
    return this.message.Associate(options);
  }

  disassociate(options) {
    return this.message.Disassociate(options);
  }

  execute(options) {
    return this.message.Execute(options);
  }

  executeSetState(options) {
    return this.message.ExecuteSetState(options);
  }

  delete(options) {
    return this.message.Delete(options);
  }
}