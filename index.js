import Serializer from 'serializer';


const serializer = new Serializer();

export class Dynamics {
  constructor(settings) {
    const util = new Util(settings);
    this.message = new Message(util);
  }

  create(options) {
    const template = `
			<s:Body>
				<Create xmlns="http://schemas.microsoft.com/xrm/2011/Contracts/Services"  xmlns:b="http://schemas.microsoft.com/xrm/2011/Contracts" xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns:c="http://schemas.datacontract.org/2004/07/System.Collections.Generic">
					<entity>
						{requetbody}
					</entity>
				</Create>
			</s:Body>`;

    return util.executePostPromised(options, "Create", template, serializer.toXmlCreateUpdate(options));
  }

  update(options) {
    const template = `
			<s:Body>
				<Update xmlns="http://schemas.microsoft.com/xrm/2011/Contracts/Services"  xmlns:b="http://schemas.microsoft.com/xrm/2011/Contracts" xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns:c="http://schemas.datacontract.org/2004/07/System.Collections.Generic">
					<entity>
						{requetbody}
					</entity>
				</Update>
			</s:Body>`;

    return util.executePostPromised(options, "Update", template, serializer.toXmlCreateUpdate(options));
  }

  retrieve(options) {
    const template = `
			<s:Body>
				<Retrieve xmlns="http://schemas.microsoft.com/xrm/2011/Contracts/Services"  xmlns:b="http://schemas.microsoft.com/xrm/2011/Contracts" xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns:c="http://schemas.microsoft.com/2003/10/Serialization/Arrays">
					{requetbody}
				</Retrieve>
			</s:Body>`;

    return util.executePostPromised(options, "Retrieve", template, serializer.toXmlRetrieve(options));
  }

  retrieveMultiple(options) {
    const template = `
			<s:Body>
				<RetrieveMultiple xmlns="http://schemas.microsoft.com/xrm/2011/Contracts/Services">
					<query 
						i:type="b:QueryExpression"
						xmlns:b="http://schemas.microsoft.com/xrm/2011/Contracts"
						xmlns:i="http://www.w3.org/2001/XMLSchema-instance"
						xmlns:c="http://schemas.microsoft.com/2003/10/Serialization/Arrays">
						{requetbody}
					</query>
				</RetrieveMultiple>
			</s:Body>`;

    return executePostPromised(options, "RetrieveMultiple", template, serializer.toXmlRetrieveMultiple(options));
  }

  associate(options) {
    const template = `
			<s:Body>
				<Associate xmlns="http://schemas.microsoft.com/xrm/2011/Contracts/Services"  xmlns:b="http://schemas.microsoft.com/xrm/2011/Contracts" xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns:c="http://schemas.datacontract.org/2004/07/System.Collections.Generic">
					{requetbody}
				</Associate>
			</s:Body>`;

    return util.executePostPromised(options, "Associate", template, serializer.toXmlAssociate(options));
  }

  disassociate(options) {
    const template = `
			<s:Body>
				<Disassociate xmlns="http://schemas.microsoft.com/xrm/2011/Contracts/Services"  xmlns:b="http://schemas.microsoft.com/xrm/2011/Contracts" xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns:c="http://schemas.datacontract.org/2004/07/System.Collections.Generic">
					{requetbody}
				</Disassociate>
			</s:Body>`;

    return util.executePostPromised(options, "Disassociate", template, serializer.toXmlAssociate(options));
  }

  execute(options) {
    var template = `
			<s:Body>
				<Execute xmlns="http://schemas.microsoft.com/xrm/2011/Contracts/Services"  xmlns:b="http://schemas.microsoft.com/xrm/2011/Contracts" xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns:c="http://schemas.datacontract.org/2004/07/System.Collections.Generic">
					<!--Optional:-->
					<request>
						{requetbody}
					</request>
				</Execute>
			</s:Body>`;

    return util.executePostPromised(options, "Execute", template, serializer.toXmlExecute(options));
  }

  delete(options) {
    const template = `
			<s:Body>
				<Delete xmlns="http://schemas.microsoft.com/xrm/2011/Contracts/Services"  xmlns:b="http://schemas.microsoft.com/xrm/2011/Contracts" xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns:c="http://schemas.datacontract.org/2004/07/System.Collections.Generic">
					{requetbody}
				</Delete>
			</s:Body>`;

    return util.executePostPromised(options, "Delete", template, serializer.toXmlDelete(options));
  }
}