import api from "./api";

export async function getReport() {

    const response = await api.get("/reports/windows");

    return response.data;
}

export async function investigateEvent(eventData) {

    const response = await api.post("/ai/investigate", {

        event: eventData

    });

    return response.data;
}

export async function chatWithAI(question) {

    const response = await api.post("/ai/chat", {

        question

    });

    return response.data;
}