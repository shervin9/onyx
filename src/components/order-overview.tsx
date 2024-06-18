"use client"
import {useAppContext} from "@/providers/context-provider";
import OrderItem from "@/components/order-item";

export default function OrderOverview() {
    const {state, dispatch} = useAppContext()

    const items = Array.from(state.cart.values())
        .map((cartItem) => <OrderItem key={cartItem.product.id} id={cartItem.product.id}/>)

    return (
        <section className="order-overview" dir="rtl">
            <div className="order-block">
                <div className="order-header-wrap">
                    <h2 className="order-header">سفارش شما</h2>
                    <span className="order-edit"
                          onClick={() => dispatch({type: "storefront"})}>ویرایش</span>
                </div>
                <div className="order-items">
                    {items}
                </div>
            </div>
            <div className="order-text-field-wrap">
                    <textarea
                        className="order-text-field order-block"
                        rows={1}
                        placeholder="نام"
                        onChange={(e) =>
                            dispatch({type: "address", address: e.currentTarget.value})
                        }
                    ></textarea>
                    <textarea
                        className="order-text-field order-block"
                        rows={1}
                        placeholder="نام خانوادگی"
                        onChange={(e) =>
                            dispatch({type: "address", address: e.currentTarget.value})
                        }
                    ></textarea>
                <div className="order-text-field-hint">
                    مشخصات مشتری
                </div>
            </div>
            <div className="order-text-field-wrap">
                    <textarea
                        className="order-text-field order-block"
                        rows={1}
                        placeholder="Your Address…"
                        onChange={(e) =>
                            dispatch({type: "address", address: e.currentTarget.value})
                        }
                    ></textarea>
                <div className="order-text-field-hint">
                    Shipping Address
                </div>
            </div>
            <div className="order-text-field-wrap">
                    <textarea
                        className="order-text-field order-block"
                        rows={1}
                        placeholder="توضیحات …"
                        onChange={(e) =>
                            dispatch({type: "comment", comment: e.currentTarget.value})
                        }
                    ></textarea>
                <div className="order-text-field-hint">
                    توضیحات، جزییات و یا درخواست های شما...
                </div>
            </div>
        </section>
    )
}
