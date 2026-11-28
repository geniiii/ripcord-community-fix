static u8 ss_is_async(IMFTransform* transform) {
    IMFAttributes* attributes = NULL;
    UINT32         is_async   = 0;
    if (SUCCEEDED(IMFTransform_GetAttributes(transform, &attributes)) && attributes) {
        IMFAttributes_GetUINT32(attributes, &MF_TRANSFORM_ASYNC, &is_async);
        IMFAttributes_Release(attributes);
    }
    return is_async != 0;
}

static HRESULT ss_set_out_type(IMFTransform* encoder, u32 bitrate, u8 with_profile) {
    ss_engine*    e    = &g_engine;
    IMFMediaType* type = NULL;
    MFCreateMediaType(&type);
    IMFMediaType_SetGUID(type, &MF_MT_MAJOR_TYPE, &MFMediaType_Video);
    IMFMediaType_SetGUID(type, &MF_MT_SUBTYPE, &MFVideoFormat_H264);
    IMFMediaType_SetUINT32(type, &MF_MT_AVG_BITRATE, bitrate);
    IMFMediaType_SetUINT64(type, &MF_MT_FRAME_SIZE, ss_pack_pair((u32) e->enc_w, (u32) e->enc_h));
    IMFMediaType_SetUINT64(type, &MF_MT_FRAME_RATE, ss_pack_pair((u32) e->fps, 1));
    IMFMediaType_SetUINT64(type, &MF_MT_PIXEL_ASPECT_RATIO, ss_pack_pair(1, 1));
    IMFMediaType_SetUINT32(type, &MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);
    // Baseline: no B-frames and no reordering, so decode order is display order and the capture-order
    // timestamps stay valid
    if (with_profile) {
        IMFMediaType_SetUINT32(type, &MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_Base);
    }
    HRESULT hr = IMFTransform_SetOutputType(encoder, 0, type, 0);
    IMFMediaType_Release(type);
    return hr;
}

static u8 ss_config_enc(IMFTransform* encoder, u32 bitrate, u8 hardware) {
    ss_engine* e = &g_engine;

    if (hardware) {
        // GPU encoders are asynchronous: they refuse to work until unlocked, then report readiness as events
        IMFAttributes* attributes = NULL;
        if (SUCCEEDED(IMFTransform_GetAttributes(encoder, &attributes)) && attributes) {
            UINT32 is_async = 0;
            IMFAttributes_GetUINT32(attributes, &MF_TRANSFORM_ASYNC, &is_async);
            if (is_async) {
                IMFAttributes_SetUINT32(attributes, &MF_TRANSFORM_ASYNC_UNLOCK, TRUE);
            }
            IMFAttributes_SetUINT32(attributes, &MF_LOW_LATENCY, TRUE);
            IMFAttributes_Release(attributes);
        }
    }

    HRESULT hr = ss_set_out_type(encoder, bitrate, 1);
    // Some GPU encoders reject the profile in the media type. They default to one viewers can decode, and
    // B-frames are switched off through the codec API below
    if (FAILED(hr) && hardware) {
        hr = ss_set_out_type(encoder, bitrate, 0);
    }
    if (FAILED(hr)) {
        return 0;
    }

    IMFMediaType* in_type = NULL;
    MFCreateMediaType(&in_type);
    IMFMediaType_SetGUID(in_type, &MF_MT_MAJOR_TYPE, &MFMediaType_Video);
    IMFMediaType_SetGUID(in_type, &MF_MT_SUBTYPE, &MFVideoFormat_NV12);
    IMFMediaType_SetUINT64(in_type, &MF_MT_FRAME_SIZE, ss_pack_pair((u32) e->enc_w, (u32) e->enc_h));
    IMFMediaType_SetUINT64(in_type, &MF_MT_FRAME_RATE, ss_pack_pair((u32) e->fps, 1));
    IMFMediaType_SetUINT64(in_type, &MF_MT_PIXEL_ASPECT_RATIO, ss_pack_pair(1, 1));
    IMFMediaType_SetUINT32(in_type, &MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);
    hr = IMFTransform_SetInputType(encoder, 0, in_type, 0);
    IMFMediaType_Release(in_type);
    if (FAILED(hr)) {
        return 0;
    }

    ICodecAPI* codec = NULL;
    if (SUCCEEDED(IMFTransform_QueryInterface(encoder, &IID_ICodecAPI, (void**) &codec)) && codec) {
        VARIANT v;
        VariantInit(&v);

        V_VT(&v)   = VT_BOOL;
        V_BOOL(&v) = VARIANT_TRUE;
        ICodecAPI_SetValue(codec, &CODECAPI_AVEncCommonLowLatency, &v);

        V_VT(&v)  = VT_UI4;
        V_UI4(&v) = eAVEncCommonRateControlMode_CBR;
        ICodecAPI_SetValue(codec, &CODECAPI_AVEncCommonRateControlMode, &v);

        V_VT(&v)  = VT_UI4;
        V_UI4(&v) = bitrate;
        ICodecAPI_SetValue(codec, &CODECAPI_AVEncCommonMeanBitRate, &v);

        // A keyframe every two seconds. Without this the encoders pick their own, much shorter, interval
        V_VT(&v)  = VT_UI4;
        V_UI4(&v) = (u32) e->fps * 2;
        ICodecAPI_SetValue(codec, &CODECAPI_AVEncMPVGOPSize, &v);

        if (hardware) {
            V_VT(&v)  = VT_UI4;
            V_UI4(&v) = 0;
            ICodecAPI_SetValue(codec, &CODECAPI_AVEncMPVDefaultBPictureCount, &v);
        }
        ICodecAPI_Release(codec);
    }

    if (FAILED(IMFTransform_ProcessMessage(encoder, MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0))) {
        return 0;
    }
    IMFTransform_ProcessMessage(encoder, MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);
    return 1;
}

static void ss_free_encoder(void) {
    ss_engine* e = &g_engine;
    if (e->mf && e->hardware) {
        IMFTransform_ProcessMessage(e->mf, MFT_MESSAGE_COMMAND_FLUSH, 0);
    }
    ss_release(e->events);
    ss_release(e->mf);
    if (e->activate) {
        IMFActivate_ShutdownObject(e->activate);
        ss_release(e->activate);
    }
    e->hardware   = 0;
    e->async      = 0;
    e->need_input = 0;
    for (i32 i = 0; i < e->queue_count; ++i) {
        ss_bytes_free(&e->queue[i]);
    }
    e->queue_count = 0;
}

static u8 ss_try_gpu_encoder(u32 bitrate) {
    ss_engine*             e           = &g_engine;
    MFT_REGISTER_TYPE_INFO input_info  = { MFMediaType_Video, MFVideoFormat_NV12 };
    MFT_REGISTER_TYPE_INFO output_info = { MFMediaType_Video, MFVideoFormat_H264 };

    IMFActivate** activates = NULL;
    UINT32        count     = 0;
    HRESULT       hr        = MFTEnumEx(MFT_CATEGORY_VIDEO_ENCODER, MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER,
                                        &input_info, &output_info, &activates, &count);
    if (FAILED(hr) || count == 0 || !activates) {
        if (activates) {
            CoTaskMemFree(activates);
        }
        return 0;
    }

    u8 found = 0;
    for (UINT32 i = 0; i < count && !found; ++i) {
        IMFTransform* encoder = NULL;
        if (FAILED(IMFActivate_ActivateObject(activates[i], &IID_IMFTransform, (void**) &encoder)) || !encoder) {
            continue;
        }

        u8                      is_async  = ss_is_async(encoder);
        IMFMediaEventGenerator* generator = NULL;
        if (is_async) {
            IMFTransform_QueryInterface(encoder, &IID_IMFMediaEventGenerator, (void**) &generator);
        }

        if ((!is_async || generator) && ss_config_enc(encoder, bitrate, 1)) {
            e->mf       = encoder;
            e->events   = generator;
            e->async    = is_async;
            e->hardware = 1;
            e->activate = activates[i];
            IMFActivate_AddRef(activates[i]);

            WCHAR* name        = NULL;
            UINT32 name_length = 0;
            if (SUCCEEDED(IMFActivate_GetAllocatedString(activates[i], &MFT_FRIENDLY_NAME_Attribute, &name, &name_length)) && name) {
                wcsncpy(g_ss_stats.encoder, name, ArrayCount(g_ss_stats.encoder) - 1);
                CoTaskMemFree(name);
            } else {
                wcscpy(g_ss_stats.encoder, L"Hardware H.264");
            }
            found = 1;
        } else {
            ss_release(generator);
            IMFTransform_Release(encoder);
            IMFActivate_ShutdownObject(activates[i]);
        }
    }

    for (UINT32 i = 0; i < count; ++i) {
        IMFActivate_Release(activates[i]);
    }
    CoTaskMemFree(activates);
    return found;
}

static u8 ss_soft_encoder(u32 bitrate) {
    ss_engine*    e       = &g_engine;
    IMFTransform* encoder = NULL;
    HRESULT       hr      = CoCreateInstance(&CLSID_CMSH264EncoderMFT, NULL, CLSCTX_INPROC_SERVER, &IID_IMFTransform, (void**) &encoder);
    if (FAILED(hr) || !encoder) {
        return 0;
    }
    if (!ss_config_enc(encoder, bitrate, 0)) {
        IMFTransform_Release(encoder);
        return 0;
    }
    e->mf       = encoder;
    e->hardware = 0;
    e->async    = 0;
    wcscpy(g_ss_stats.encoder, L"Software H.264 (Media Foundation)");
    return 1;
}

static u8 ss_init_encoder(u8 prefer_hardware) {
    ss_engine* e = &g_engine;
    ss_free_encoder();
    e->mf_timestamp = 0;
    ss_bytes_free(&e->sps_pps);
    e->empty_frames       = 0;
    g_ss_stats.encoder[0] = 0;

    if (prefer_hardware && ss_try_gpu_encoder(e->bitrate)) {
        g_ss_stats.hardware = 1;
        return 1;
    }
    g_ss_stats.hardware = 0;
    return ss_soft_encoder(e->bitrate);
}

static void ss_build_sps_pps(void) {
    ss_engine* e = &g_engine;
    if (!e->mf) {
        return;
    }
    IMFMediaType* type = NULL;
    if (FAILED(IMFTransform_GetOutputCurrentType(e->mf, 0, &type)) || !type) {
        return;
    }
    UINT32 blob_size = 0;
    if (FAILED(IMFMediaType_GetBlobSize(type, &MF_MT_MPEG_SEQUENCE_HEADER, &blob_size)) || blob_size == 0) {
        IMFMediaType_Release(type);
        return;
    }
    u8* blob = (u8*) malloc(blob_size);
    if (blob && SUCCEEDED(IMFMediaType_GetBlob(type, &MF_MT_MPEG_SEQUENCE_HEADER, blob, blob_size, NULL))) {
        ss_bytes annex_b = { 0 };
        if (ss_sps_pps_to_annex_b(blob, blob_size, &annex_b)) {
            e->sps_pps = annex_b;
        } else {
            ss_bytes_free(&annex_b);
            ss_bytes_append(&annex_b, blob, blob_size);
            ss_to_annex_b(&annex_b);
            if (ss_has_start_code(annex_b.data, annex_b.size)) {
                e->sps_pps = annex_b;
            } else {
                ss_bytes_free(&annex_b);
            }
        }
    }
    free(blob);
    IMFMediaType_Release(type);
}

static void ss_finalize_frame(ss_bytes* frame) {
    ss_engine* e = &g_engine;
    ss_to_annex_b(frame);
    if (frame->size && ss_has_nal(frame->data, frame->size, 5)) {
        if (e->sps_pps.size == 0) {
            ss_build_sps_pps();
        }
        u8 has_sps = ss_has_nal(frame->data, frame->size, 7);
        u8 has_pps = ss_has_nal(frame->data, frame->size, 8);
        if (e->sps_pps.size && (!has_sps || !has_pps)) {
            ss_bytes_prepend(frame, e->sps_pps.data, e->sps_pps.size);
        }
    }
}

static void ss_queue_frame(ss_bytes* frame) {
    ss_engine* e = &g_engine;
    if (frame->size == 0) {
        ss_bytes_free(frame);
        return;
    }
    if (e->queue_count == ss_queue_max) {
        ss_bytes_free(&e->queue[0]);
        memmove(&e->queue[0], &e->queue[1], (ss_queue_max - 1) * sizeof e->queue[0]);
        --e->queue_count;
    }
    e->queue[e->queue_count++] = *frame;
    memset(frame, 0, sizeof *frame);
}

typedef enum {
    ss_read_data,
    ss_read_none,
    ss_read_retry,
} ss_read_result;

static ss_read_result ss_read_out(ss_bytes* out) {
    ss_engine*    e       = &g_engine;
    IMFTransform* encoder = e->mf;

    MFT_OUTPUT_STREAM_INFO stream_info = { 0 };
    IMFTransform_GetOutputStreamInfo(encoder, 0, &stream_info);
    u8 provides_samples = (stream_info.dwFlags & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES)) != 0;

    IMFSample* sample = NULL;
    if (!provides_samples) {
        DWORD size = stream_info.cbSize > 1024 * 1024 ? stream_info.cbSize : 1024 * 1024;
        MFCreateSample(&sample);
        IMFMediaBuffer* buffer = NULL;
        MFCreateMemoryBuffer(size, &buffer);
        IMFSample_AddBuffer(sample, buffer);
        IMFMediaBuffer_Release(buffer);
    }

    MFT_OUTPUT_DATA_BUFFER data = { 0 };
    data.pSample                = sample;
    DWORD   status              = 0;
    HRESULT hr                  = IMFTransform_ProcessOutput(encoder, 0, 1, &data, &status);
    if (data.pEvents) {
        IMFCollection_Release(data.pEvents);
        data.pEvents = NULL;
    }
    IMFSample* result = data.pSample;

    if (hr == MF_E_TRANSFORM_STREAM_CHANGE) {
        if (result) {
            IMFSample_Release(result);
        }
        IMFMediaType* type = NULL;
        if (SUCCEEDED(IMFTransform_GetOutputAvailableType(encoder, 0, 0, &type)) && type) {
            IMFTransform_SetOutputType(encoder, 0, type, 0);
            IMFMediaType_Release(type);
        }
        return ss_read_retry;
    }
    if (FAILED(hr) || !result) {
        // MF_E_TRANSFORM_NEED_MORE_INPUT is the normal "nothing more to read" answer
        if (result) {
            IMFSample_Release(result);
        }
        return ss_read_none;
    }

    IMFMediaBuffer* contiguous = NULL;
    IMFSample_ConvertToContiguousBuffer(result, &contiguous);
    if (contiguous) {
        BYTE* bytes  = NULL;
        DWORD length = 0;
        IMFMediaBuffer_Lock(contiguous, &bytes, NULL, &length);
        ss_bytes_append(out, bytes, length);
        IMFMediaBuffer_Unlock(contiguous);
        IMFMediaBuffer_Release(contiguous);
    }
    IMFSample_Release(result);
    return out->size ? ss_read_data : ss_read_none;
}

static void ss_pump_events(void) {
    ss_engine* e = &g_engine;
    if (!e->events) {
        return;
    }
    for (;;) {
        IMFMediaEvent* event = NULL;
        HRESULT        hr    = IMFMediaEventGenerator_GetEvent(e->events, MF_EVENT_FLAG_NO_WAIT, &event);
        if (FAILED(hr) || !event) {
            break;
        }
        MediaEventType type = MEUnknown;
        IMFMediaEvent_GetType(event, &type);
        IMFMediaEvent_Release(event);

        if (type == METransformNeedInput) {
            ++e->need_input;
        } else if (type == METransformHaveOutput) {
            for (i32 attempt = 0; attempt < 3; ++attempt) {
                ss_bytes       piece  = { 0 };
                ss_read_result result = ss_read_out(&piece);
                if (result == ss_read_retry) {
                    ss_bytes_free(&piece);
                    continue;
                }
                if (result == ss_read_data) {
                    ss_finalize_frame(&piece);
                    ss_queue_frame(&piece);
                }
                ss_bytes_free(&piece);
                break;
            }
        }
    }
}

static void ss_encode_sync(IMFSample* sample) {
    ss_engine* e  = &g_engine;
    HRESULT    hr = IMFTransform_ProcessInput(e->mf, 0, sample, 0);
    IMFSample_Release(sample);
    if (FAILED(hr)) {
        return;
    }

    ss_bytes raw = { 0 };
    for (i32 attempt = 0; attempt < 8; ++attempt) {
        ss_bytes       piece  = { 0 };
        ss_read_result result = ss_read_out(&piece);
        if (result == ss_read_data) {
            ss_bytes_append(&raw, piece.data, piece.size);
            ss_bytes_free(&piece);
            continue;
        }
        ss_bytes_free(&piece);
        if (result == ss_read_retry) {
            continue;
        }
        break;
    }
    if (raw.size) {
        ss_finalize_frame(&raw);
        ss_queue_frame(&raw);
    }
    ss_bytes_free(&raw);
}

static void ss_encode_async(IMFSample* sample) {
    ss_engine* e  = &g_engine;
    HRESULT    hr = IMFTransform_ProcessInput(e->mf, 0, sample, 0);
    IMFSample_Release(sample);
    if (FAILED(hr)) {
        return;
    }
    if (e->need_input > 0) {
        --e->need_input;
    }

    // Hardware encoders answer within a few milliseconds. Wait briefly so the frame goes out in this tick, but
    // never long enough to wreck the frame pacing. A frame that isn't ready yet is collected on the next tick
    u64 start = ss_now_ms();
    ss_pump_events();
    while (e->queue_count == 0 && ss_now_ms() - start < 4) {
        Sleep(1);
        ss_pump_events();
    }
}

static void ss_force_key(void) {
    ICodecAPI* codec = NULL;
    if (SUCCEEDED(IMFTransform_QueryInterface(g_engine.mf, &IID_ICodecAPI, (void**) &codec)) && codec) {
        VARIANT v;
        VariantInit(&v);
        V_VT(&v)  = VT_UI4;
        V_UI4(&v) = 1;
        ICodecAPI_SetValue(codec, &CODECAPI_AVEncVideoForceKeyFrame, &v);
        ICodecAPI_Release(codec);
    }
}

static void ss_encode_nv12(const ss_bytes* nv12, u8 force_key_frame) {
    ss_engine* e = &g_engine;
    if (!e->mf) {
        return;
    }

    if (e->async) {
        ss_pump_events();
        u64 start = ss_now_ms();
        while (e->need_input == 0 && ss_now_ms() - start < (u64) e->interval_ms) {
            Sleep(1);
            ss_pump_events();
        }
        if (e->need_input == 0) {
            return;
        }
    }

    if (force_key_frame) {
        ss_force_key();
    }

    IMFMediaBuffer* buffer = NULL;
    if (FAILED(MFCreateMemoryBuffer(nv12->size, &buffer))) {
        return;
    }
    BYTE* data = NULL;
    IMFMediaBuffer_Lock(buffer, &data, NULL, NULL);
    memcpy(data, nv12->data, nv12->size);
    IMFMediaBuffer_Unlock(buffer);
    IMFMediaBuffer_SetCurrentLength(buffer, nv12->size);

    IMFSample* sample = NULL;
    MFCreateSample(&sample);
    IMFSample_AddBuffer(sample, buffer);
    IMFMediaBuffer_Release(buffer);

    LONGLONG duration = 10000000LL / e->fps;
    IMFSample_SetSampleTime(sample, (LONGLONG) e->mf_timestamp);
    IMFSample_SetSampleDuration(sample, duration);
    e->mf_timestamp += (u64) duration;

    if (e->async) {
        ss_encode_async(sample);
    } else {
        ss_encode_sync(sample);
    }
}

static u8 ss_fall_back(void) {
    ss_free_encoder();
    if (!ss_init_encoder(0)) {
        ss_fail(L"The GPU encoder stopped producing video and the software encoder couldn't start.");
        return 0;
    }
    g_engine.need_key = 1;
    return 1;
}
