import {createClient} from "@supabase/supabase-js";
export function userClient(jwt:string){const url=process.env.SUPABASE_URL;const key=process.env.SUPABASE_PUBLISHABLE_KEY;if(!url||!key)throw new Error("Missing Supabase configuration");return createClient(url,key,{global:{headers:{Authorization:`Bearer ${jwt}`}},auth:{persistSession:false,autoRefreshToken:false}})}
