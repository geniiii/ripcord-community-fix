// NOTE(geni): List size limit + 1
//             Maps can be larger than this, but they're flagged
//             by setting the least-significant bit and hence take a different path
#define DEDFRAME_TUPLE_FLAG 0x8000000
static DED_STEP(DedStepHook) {
    if (s->index != 255) {
        DedFrame frame = s->frames[s->index];
        // NOTE(geni): Take tuple path instead of list path to avoid skipping NIL_EXT on accident.
        //             See Ded::Step in IDA if confused
        if (frame == DEDFRAME_TUPLE_FLAG) {
            ++s->index;
            result->event.type = DedEventType_ListEnd;
            result->type       = DedResultType_Event;
            return result;
        }

        // NOTE(geni): Original Ded::Step logic
        if (frame < 2) {
            return ded_step(result, s);
        }
    }

    u64 term_size = s->length;
    u8* term_data = s->data;
    // NOTE(geni): The dreaded-by-packers ETF type 104/'h' (SMALL_TUPLE_EXT)
    if (term_size == 0 || *term_data != DedETFTerm_SmallTuple) {
        return ded_step(result, s);
    }

    // NOTE(geni): This is done at the top of Ded::Step, which means
    //             we have to move it down here to avoid decrementing twice
    if (s->index != 255) {
        DedFrame frame = s->frames[s->index];
        s->frames[s->index] =
            (DedFrame) ((frame & 1) | (2 * (frame >> 1) - 2));
    }

    if (term_size < 2) {
        result->error.type = DedErrorType_EndedUnexpectedly;
        result->type       = DedResultType_Error;
        return result;
    }

    u8 arity = term_data[1];
    if (s->index == 0) {
        result->error.type = DedErrorType_ExceededSizeLimit;
        result->type       = DedResultType_Error;
        return result;
    }
    result->event.type    = DedEventType_ListStart;
    s->frames[--s->index] = DEDFRAME_TUPLE_FLAG | (2 * arity);

    result->event.int64 = arity;
    result->type        = DedResultType_Event;

    s->data += 2;
    s->length -= 2;

    return result;
}
