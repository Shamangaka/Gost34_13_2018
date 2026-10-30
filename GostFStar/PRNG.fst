module PRNG
open FStar.Pervasives.Native

type rng_state = { x: UInt32.t }

let init : UInt32.t -> rng_state = 
    fun (state) -> { x = state }

let rnext (state: rng_state) : rng_state & UInt8.t =
    let new_x = UInt32.add_mod(UInt32.mul_mod 1103515245ul state.x) 12345ul in
    let sh = UInt32.shift_right new_x 16ul in
    let next_val = Int.Cast.uint32_to_uint8 sh in
    (* bits 23..16 of the new state, as in the reference code (previously the
       whole shifted 32-bit value was returned) *)
    Mktuple2 { x = new_x } next_val
