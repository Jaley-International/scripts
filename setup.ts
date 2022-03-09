import chalk from "chalk";
import inquirer, {Answers} from "inquirer";
import {
    addPadding, encrypt,
    generateKeyPair,
    hexToBase64Url,
    pbkdf2,
    randomBytes,
    rsaSign,
    sha256,
    sha512,
    truncateKey
} from "./util";
import forge, {Hex} from "node-forge";
import {Spinner} from "cli-spinner";

async function welcome(): Promise<Answers> {
    console.clear();

    console.log(`${chalk.bgBlueBright("                          ")}`);
    console.log(`${chalk.bold(chalk.bgBlueBright("          WELCOME         "))}`);
    console.log(`${chalk.bgBlueBright("                          ")}\n`);

    console.log(`${chalk.bold("Private Encrypted Cloud")}  -  Keep control over your data\n`);
    console.log("You are entering scripts mode.");
    console.log("Please ensure that the API is online and in scripts mode.\n");

    const response = await inquirer.prompt({
        name: "continue",
        type: "confirm",
        message: "Are you sure you want to continue?",
        default: false
    });
    return response.continue;
}


interface InstanceConfiguration {
    instanceId: string;
    serverRandomValue: string;
    instancePublicKey: string;
    instancePrivateKey: string;
    instancePublicKeySignature: string;
    apiUrl: string;
    clientUrl: string;
    mysqlUriPrompt: string;
    port: number;
    sessionExpireTimer: number;
    tmpFileExpire: number;
}

async function configureInstance(): Promise<InstanceConfiguration> {
    console.log(`\n\n${chalk.bgBlueBright("                          ")}`);
    console.log(`${chalk.bold(chalk.bgBlueBright("  INSTANCE CONFIGURATION  "))}`);
    console.log(`${chalk.bgBlueBright("                          ")}\n`);

    // Generate Instance ID and Server Random Value
    const instanceId = randomBytes(4);
    const serverRandomValue = randomBytes(16);

    // Generate sharing keypair
    const instanceKeypair = await generateKeyPair();
    const [privateKey, publicKey] = [
        forge.pki.privateKeyToPem(instanceKeypair.privateKey),
        forge.pki.publicKeyToPem(instanceKeypair.publicKey)
    ];
    const instancePublicKeySignature = rsaSign(privateKey, publicKey);

    const instance = await inquirer.prompt([{
        name: "apiUrl",
        type: "input",
        message: "API URL",
        validate: (input: string) => input.length > 0
    }, {
        name: "clientUrl",
        type: "input",
        message: "Client URL",
        validate: (input: string) => input.length > 0
    }, {
        name: "mysqlUri",
        type: "input",
        message: "MySQL URI",
        validate: (input: string) => input.length > 0
    }, {
        name: "port",
        type: "input",
        message: "API port",
        default: 3001,
        validate: (input: any) => typeof input === "number"
    }, {
        name: "sessionExpireTimer",
        type: "input",
        message: "Session max idle time (in seconds)",
        default: 1800,
        validate: (input: any) => typeof input === "number"
    }, {
        name: "tmpFileExpire",
        type: "input",
        message: "Temporary file expiration delay (in seconds)",
        default: 30,
        validate: (input: any) => typeof input === "number"
    }]);

    return {
        apiUrl: instance.apiUrl,
        clientUrl: instance.clientUrl,
        mysqlUriPrompt: instance.mysqlUri,
        port: instance.port,
        sessionExpireTimer: instance.sessionExpireTimer,
        tmpFileExpire: instance.tmpFileExpire,
        instanceId: instanceId,
        instancePrivateKey: privateKey,
        instancePublicKey: publicKey,
        instancePublicKeySignature: instancePublicKeySignature,
        serverRandomValue: serverRandomValue
    };
}


interface AdminProperties {
    firstName: string;
    lastName: string;
    username: string;
    email: string;
    group: string;
    job: string;
    registrationKey: string;
    publicSharingKey: string;
    privateSharingKey: string;
    clientRandomValue: Hex;
    encryptedMasterKey: Hex;
    masterKey: Hex;
    hashedAuthenticationKey: Hex;
    encryptedPrivateSharingKey: Hex;
    encryptedInstancePublicKey: Hex
    encryptedInstancePrivateKey: Hex;
    publicSharingKeySignature: Hex;
}

async function createAdministrator(instanceConfiguration: InstanceConfiguration): Promise<AdminProperties> {
    console.log(`\n\n${chalk.bgBlueBright("                          ")}`);
    console.log(`${chalk.bold(chalk.bgBlueBright("  ADMINISTRATOR CREATION  "))}`);
    console.log(`${chalk.bgBlueBright("                          ")}\n`);

    const user = await inquirer.prompt([{
        name: "firstName",
        type: "input",
        message: "First name",
        validate: (input: string) => /^[0-9a-zA-Z-]{0,32}$/.test(input)
    }, {
        name: "lastName",
        type: "input",
        message: "Last name",
        validate: (input: string) => /^[0-9a-zA-Z-]{0,32}$/.test(input)
    }, {
        name: "username",
        type: "input",
        message: "Username",
        validate: (input: string) => /^[0-9a-zA-Z-]{3,16}$/.test(input)
    }, {
        name: "email",
        type: "input",
        message: "Email address",
        validate: (input: string) => input.length > 0
    }, {
        name: "group",
        type: "input",
        message: "Group / Department",
        default: "Executives",
        validate: (input: string) => input.length > 0
    }, {
        name: "job",
        type: "input",
        message: "Job title",
        default: "CEO",
        validate: (input: string) => input.length > 0
    }]);

    let password;
    do {
        if (password)
            console.log(`\n${chalk.bold(chalk.bgRed(" ERROR "))} ${chalk.redBright("Passwords did not match. Please retry.")}`);
        password = await inquirer.prompt([{
            name: "password",
            type: "password",
            message: "Password",
            validate: (input: string) => input.length > 0
        }, {
            name: "confirmation",
            type: "password",
            message: "Password (confirmation)",
            validate: (input: string) => input.length > 0
        }]);
    } while (!password || password["password"] !== password["confirmation"]);

    console.log("\n");
    const spinner = new Spinner({text: "Generating keys..."})
        .setSpinnerString("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
        .setSpinnerDelay(50)
        .start();

    const registrationKey = hexToBase64Url(randomBytes(12));
    const instanceKeypair = await generateKeyPair();
    const [privateKey, publicKey] = [
        forge.pki.privateKeyToPem(instanceKeypair.privateKey),
        forge.pki.publicKeyToPem(instanceKeypair.publicKey)
    ];

    const masterKey = randomBytes(32);
    const clientRandomValue = randomBytes(16);
    const salt = sha256(addPadding(registrationKey + instanceConfiguration.instanceId + clientRandomValue, 128));

    const derivedKey = await pbkdf2(password["password"], salt);
    const derivedEncryptionKey = derivedKey.substring(0, 64);
    const derivedAuthenticationKey = derivedKey.substring(64);

    const encryptedPrivateSharingKey = encrypt("AES-CTR", masterKey, salt, privateKey);
    const encryptedInstancePublicKey = encrypt("AES-CTR", masterKey, salt, instanceConfiguration.instancePublicKey);
    const encryptedInstancePrivateKey = encrypt("AES-CTR", masterKey, salt, instanceConfiguration.instancePrivateKey);
    const encryptedMasterKey = encrypt("AES-CTR", derivedEncryptionKey, salt, masterKey);
    const hashedAuthenticationKey = sha512(derivedAuthenticationKey);
    const publicSharingKeySignature = rsaSign(instanceConfiguration.instancePrivateKey, publicKey);

    spinner.stop(true);

    return {
        firstName: user["firstName"],
        lastName: user["lastName"],
        username: user["username"],
        email: user["email"],
        group: user["group"],
        job: user["job"],
        registrationKey: registrationKey,
        publicSharingKey: publicKey,
        privateSharingKey: privateKey,
        clientRandomValue: clientRandomValue,
        masterKey: masterKey,
        encryptedMasterKey: encryptedMasterKey,
        hashedAuthenticationKey: hashedAuthenticationKey,
        encryptedPrivateSharingKey: encryptedPrivateSharingKey,
        encryptedInstancePublicKey: encryptedInstancePublicKey,
        encryptedInstancePrivateKey: encryptedInstancePrivateKey,
        publicSharingKeySignature: publicSharingKeySignature
    }
}


async function summary(instanceConfiguration: InstanceConfiguration, adminProperties: AdminProperties): Promise<boolean> {
    console.log(`\n\n${chalk.bgBlueBright("                          ")}`);
    console.log(`${chalk.bold(chalk.bgBlueBright("          SUMMARY         "))}`);
    console.log(`${chalk.bgBlueBright("                          ")}\n`);

    console.log(`${chalk.bold("Instance Properties")}`);
    console.log(`    Instance ID                            ${instanceConfiguration.instanceId}`);
    console.log(`    Server Random Value                    ${instanceConfiguration.serverRandomValue}`);
    console.log(`    API URL                                ${instanceConfiguration.apiUrl}`);
    console.log(`    Instance Keys`);
    console.log(`        Public Key                         ${truncateKey(instanceConfiguration.instancePublicKey)}`);
    console.log(`        Private Key                        ${truncateKey(instanceConfiguration.instancePrivateKey)}`);
    console.log(`        Public Key Signature               ${truncateKey(instanceConfiguration.instancePublicKeySignature)}\n`);

    console.log(`${chalk.bold("Administrator")}`);
    console.log(`    Name                                   ${adminProperties.firstName} ${adminProperties.lastName}`);
    console.log(`    Group, Job                             ${adminProperties.group}, ${adminProperties.job}`);
    console.log(`    Username                               ${adminProperties.username}`);
    console.log(`    Email address                          ${adminProperties.email}`);
    console.log(`    Registration Key                       ${adminProperties.registrationKey}`);
    console.log(`    Sharing Key Pair`);
    console.log(`        Public Key                         ${truncateKey(adminProperties.publicSharingKey)}`);
    console.log(`        Private Key                        ${truncateKey(adminProperties.privateSharingKey)}`);
    console.log(`        Encrypted Private Key              ${truncateKey(adminProperties.encryptedPrivateSharingKey)}`);
    console.log(`        Public Key Signature               ${truncateKey(adminProperties.publicSharingKeySignature)}`);
    console.log(`    Master Key                             ${chalk.yellowBright(hexToBase64Url(adminProperties.masterKey))}\n`);

    const response = await inquirer.prompt({
        name: "continue",
        type: "confirm",
        message: `Save the ${chalk.yellow("Master Key")} in a safe place as a recovery method. Proceed?`,
        default: true
    });
    return response.continue;
}


async function submit(instanceConfiguration: InstanceConfiguration, adminProperties: AdminProperties): Promise<void> {
    console.log("\n");
    const spinner = new Spinner({text: "Submitting to the API..."})
        .setSpinnerString("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
        .setSpinnerDelay(50)
        .start();

    // TODO Submit data
    setTimeout(() => {
        spinner.stop(true);

        console.log(`\n${chalk.bgGreen("                          ")}`);
        console.log(`${chalk.bold(chalk.bgGreen("           DONE           "))}`);
        console.log(`${chalk.bgGreen("                          ")}\n`);

        console.log("You may now login using your credentials.\n");
    }, 5000);
}


async function main(): Promise<void> {
    if (!await welcome()) process.exit(1);
    const instanceConfig = await configureInstance();
    const adminProperties = await createAdministrator(instanceConfig);
    if (!await summary(instanceConfig, adminProperties)) process.exit(1);
    await submit(instanceConfig, adminProperties);
}

main().then(_ => {});
