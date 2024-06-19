import {OrderInfo} from "@telegraf/types";

const PAYMENT_URL = process.env.PAY_URL!!
const PAYMENT_TOKEN = process.env.PAY_TOKEN!!

function put(api: string, body: any, query?: URLSearchParams) {
    return call("PUT", api, query, body);
}

function post(api: string, body: any, query?: URLSearchParams) {
    return call("POST", api, query, body);
}

function get(api: string, query?: URLSearchParams) {
    return call("GET", api, query, undefined)
}

function call(method: string, api: string, query?: URLSearchParams, body?: any) {
    const headers = {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${PAYMENT_TOKEN}`
    };

    let url = `${PAYMENT_URL}/${api}`.replace("//", "/");
    if (!query)
        query = new URLSearchParams()
    // query.set("consumer_secret", CONSUMER_SECRET);
    // query.set("consumer_key", CONSUMER_KEY);
    url = url + "?" + query.toString();
    if (body)
        body = JSON.stringify(body)

    let init = {body, method, headers};

    console.log(`Proxy payment: ${url} | ${JSON.stringify(init)}`);

    return fetch(url, init);
}

async function createPayment(amount: Number, returnUrl: string, clientRefId: string) {
    const body = {
        "amount": amount,
        "returnUrl": returnUrl,
        "clientRefId": clientRefId
    }
    const res = await post("", body)
    return await res.json()
}

const payment = {
    get, createPayment
}

export default payment