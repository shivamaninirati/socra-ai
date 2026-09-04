import api from "./api";

export async function lookupIndicator(indicator) {

    const response = await api.post("/threat/intelligence", {

        indicator

    });

    return response.data;

}