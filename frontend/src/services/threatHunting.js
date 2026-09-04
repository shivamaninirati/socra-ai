import api from "./api";

export async function getHunts() {

    const response = await api.get("/hunt/list");

    return response.data;
}

export async function runHunt(hunt) {

    const response = await api.post("/hunt/run", {

        hunt

    });

    return response.data;
}