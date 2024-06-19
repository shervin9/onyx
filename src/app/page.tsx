"use client"
import {useCallback, useEffect} from "react";
import {useTelegram} from "@/providers/telegram-provider";
import {useAppContext} from "@/providers/context-provider";
import StoreFront from "@/components/store-front";
import OrderOverview from "@/components/order-overview";
import ProductOverview from "@/components/product-overview";

export default function Home() {
    const {webApp, user} = useTelegram()
    const {state, dispatch} = useAppContext()

    const handleCheckout = useCallback(async () => {
        console.log("checkout!")
        webApp?.MainButton.showProgress()
        const invoiceSupported = webApp?.isVersionAtLeast('6.1');
        const items = Array.from(state.cart.values()).map((item) => ({
            id: item.product.id,
            count: item.count
        }))
        const body = JSON.stringify({
            userId: user?.id,
            username: user?.username,
            chatId: webApp?.initDataUnsafe.chat?.id,
            invoiceSupported,
            comment: state.comment,
            postcode: state.postcode,
            name: state.name,
            lName: state.lName,
            phone: state.phone,
            province: state.province,
            city: state.city,
            address: state.address,
            shippingZone: state.shippingZone,
            items
        })
        console.log("-------------");
        console.log(body);
        console.log("-------------");

        try {
            const res = await fetch("api/orders", {method: "POST", body})
            const result = await res.json()

            if (invoiceSupported) {
                webApp?.openInvoice(result.invoice_link, function (status) {
                    webApp?.MainButton.hideProgress()
                    if (status == 'paid') {
                        console.log("[paid] InvoiceStatus " + result);
                        webApp?.close();
                    } else if (status == 'failed') {
                        console.log("[failed] InvoiceStatus " + result);
                        webApp?.HapticFeedback.notificationOccurred('error');
                    } else {
                        console.log("[unknown] InvoiceStatus" + result);
                        webApp?.HapticFeedback.notificationOccurred('warning');
                    }
                });
            } else {
                webApp?.showAlert("Some features not available. Please update your telegram app!")
            }
        } catch (_) {
            webApp?.showAlert("Some error occurred while processing order!")
            webApp?.MainButton.hideProgress()
        }


    }, [webApp, state.cart, state.comment, state.name, state.lName, state.phone, state.province, state.city, state.address, state.postcode, state.shippingZone])

    useEffect(() => {
        const callback = state.mode === "order" ? handleCheckout :
            () => dispatch({type: "order"})
        webApp?.MainButton.setParams({
            text_color: '#fff',
            color: '#0A84FF'
        }).onClick(callback)
        webApp?.BackButton.onClick(() => dispatch({type: "storefront"}))
        return () => {
            //prevent multiple call
            webApp?.MainButton.offClick(callback)
        }
    }, [webApp, state.mode, handleCheckout])

    useEffect(() => {
        if (state.mode === "storefront")
            webApp?.BackButton.hide()
        else
            webApp?.BackButton.show()

        if (state.mode === "order")
            webApp?.MainButton.setText("بررسی نهایی")
        else
            webApp?.MainButton.setText("مشاهده سفارش")
    }, [state.mode])

    useEffect(() => {
        if (state.cart.size !== 0) {
            webApp?.MainButton.show()
            webApp?.enableClosingConfirmation()
        } else {
            webApp?.MainButton.hide()
            webApp?.disableClosingConfirmation()
        }
    }, [state.cart.size])

    return (
        <main className={`${state.mode}-mode`}>
            <StoreFront/>
            <ProductOverview/>
            <OrderOverview/>
        </main>
    )
}
