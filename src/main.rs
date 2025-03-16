use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapCore;
use libbpf_rs::UprobeOpts;
use opentelemetry::global;
use opentelemetry::trace::TraceState;
use opentelemetry::trace::{SamplingDecision, SamplingResult};
use opentelemetry::trace::{
    Span, SpanBuilder, SpanId, SpanKind, Status, TraceContextExt, TraceId, Tracer,
};
use opentelemetry::Context;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::trace::ShouldSample;
use std::mem::MaybeUninit;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, UNIX_EPOCH};

include!(concat!(env!("OUT_DIR"), "/uprober.skel.rs"));

#[repr(C)]
#[derive(Debug)]
struct SpanInfo {
    trace_id: u64,
    span_id: u64,
    parent_span_id: u64,
    start_time: u64,
    end_time: u64,
    method_id: u64,
    method_name: [u8; 64],
}

fn process_span_event(data: &[u8]) -> i32 {
    if data.len() != std::mem::size_of::<SpanInfo>() {
        eprintln!("Invalid span event size: {}", data.len());
        return -1;
    }

    let span_info: &SpanInfo = unsafe { &*(data.as_ptr() as *const SpanInfo) };

    // Convert method_name from C string to Rust String
    let method_name = String::from_utf8_lossy(&span_info.method_name)
        .trim_end_matches('\0')
        .to_string();

    let tracer = global::tracer("uprobes");
    let start_time = UNIX_EPOCH + Duration::from_nanos(span_info.start_time);
    let end_time = UNIX_EPOCH + Duration::from_nanos(span_info.end_time);

    // Convert trace_id (u64) into 16-byte TraceId
    // ✅ Duplicate trace_id in both LSB and HSB
    let mut trace_id_bytes = [0u8; 16];
    trace_id_bytes[..8].copy_from_slice(&span_info.trace_id.to_le_bytes()); // HSB
    trace_id_bytes[8..].copy_from_slice(&span_info.trace_id.to_le_bytes()); // LSB

    let span_id_bytes = span_info.span_id.to_le_bytes();

    println!(
        "[DEBUG] Processing Span Event: Method={}, Trace ID={}, Span ID={}, Parent ID={}",
        method_name, span_info.trace_id, span_info.span_id, span_info.parent_span_id
    );

    // Check if this span has a parent
    let parent_cx = if span_info.parent_span_id != 0 {
        let parent_span_id = SpanId::from_bytes(span_info.parent_span_id.to_le_bytes());

        // Create a span context for the parent
        let parent_span_cx = opentelemetry::trace::SpanContext::new(
            TraceId::from_bytes(trace_id_bytes),
            parent_span_id,
            opentelemetry::trace::TraceFlags::SAMPLED,
            false,
            TraceState::default(),
        );

        let parent_span = tracer
            .span_builder("parent_span")
            .with_trace_id(TraceId::from_bytes(trace_id_bytes))
            .with_span_id(parent_span_id)
            .start(&tracer);

        Context::current_with_span(parent_span)
    } else {
        Context::new()
    };

    // Build the new span and assign it to the correct parent
    let span_builder = SpanBuilder::from_name(method_name.clone())
        .with_kind(SpanKind::Internal)
        .with_trace_id(TraceId::from_bytes(trace_id_bytes))
        .with_span_id(SpanId::from_bytes(span_id_bytes))
        .with_start_time(start_time)
        .with_end_time(end_time)
        .with_status(Status::Ok);

    let mut span = tracer.build_with_context(span_builder, &parent_cx);
    span.end();

    println!(
        "Span Processed - Method: {}, Trace ID={}, Span ID={}, ParentSpan ID={}",
        method_name, span_info.trace_id, span_info.span_id, span_info.parent_span_id
    );

    0
}

fn get_symbol_offset(binary_path: &Path, symbol_name: &str) -> Option<usize> {
    let output = Command::new("nm")
        .arg("-D")
        .arg(binary_path)
        .output()
        .ok()?;

    let output_str = String::from_utf8_lossy(&output.stdout);
    for line in output_str.lines() {
        if line.contains(symbol_name) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                return u64::from_str_radix(parts[0], 16).ok().map(|x| x as usize);
            }
        }
    }
    None
}

#[derive(Debug, Clone)]
struct FilteringSampler;

impl ShouldSample for FilteringSampler {
    fn should_sample(
        &self,
        _parent_context: Option<&Context>,
        _trace_id: opentelemetry::trace::TraceId,
        name: &str,
        _span_kind: &opentelemetry::trace::SpanKind,
        _attributes: &[opentelemetry::KeyValue],
        _links: &[opentelemetry::trace::Link],
    ) -> SamplingResult {
        // Filter out spans named "parent_span"
        if name == "parent_span" {
            println!("[DEBUG] Filtering out span: {}", name);
            return SamplingResult {
                decision: SamplingDecision::Drop,
                attributes: Vec::new(),
                trace_state: TraceState::default(),
            };
        }

        // Allow all other spans
        SamplingResult {
            decision: SamplingDecision::RecordAndSample,
            attributes: Vec::new(),
            trace_state: TraceState::default(),
        }
    }
}

fn main() {
    let exporter = opentelemetry_stdout::SpanExporter::default();
    let tracer_provider = SdkTracerProvider::builder()
        .with_sampler(FilteringSampler) // Use the custom sampler here
        .with_simple_exporter(exporter)
        .build();
    global::set_tracer_provider(tracer_provider);

    let methods = [
        (0, "first_function"),
        (1, "second_function"),
        (2, "third_function"),
    ];

    let mut links = Vec::new();
    std::env::set_var("LIBBPF_DEBUG", "1");

    let test_program_path = Path::new("/tmp/test_program");

    let skel_builder = UproberSkelBuilder::default();
    let mut open_obj = MaybeUninit::uninit();

    let open_skel = skel_builder
        .open(&mut open_obj)
        .expect("Failed to open skeleton");

    let skel = open_skel.load().expect("Failed to load skeleton");
    let method_names = skel.maps.method_names;

    // Populate the method_names map
    for (id, name) in methods.iter() {
        let key: u32 = *id;
        let mut value = [0u8; 64];
        let name_bytes = name.as_bytes();
        value[..name_bytes.len()].copy_from_slice(name_bytes);
        method_names
            .update(&key.to_le_bytes(), &value, libbpf_rs::MapFlags::ANY)
            .expect("Failed to update method_names map");
    }

    let uprobe = skel.progs.uprobe_test_function;
    let uretprobe = skel.progs.uretprobe_test_function;

    for (id, name) in methods.iter() {
        let opts = UprobeOpts {
            func_name: (*name).into(),
            retprobe: false,
            ref_ctr_offset: 0,
            cookie: *id as u64,
            _non_exhaustive: (),
        };
        let test_function_offset = 0;
        let uprobe_link = uprobe
            .attach_uprobe_with_opts(-1, test_program_path, test_function_offset, opts)
            .expect("Failed to attach uprobe");
        links.push(uprobe_link);

        let retprobe_opts = UprobeOpts {
            func_name: (*name).into(),
            retprobe: true,
            ref_ctr_offset: 0,
            cookie: *id as u64,
            _non_exhaustive: (),
        };

        let uretprobe_link = uretprobe
            .attach_uprobe_with_opts(-1, test_program_path, test_function_offset, retprobe_opts)
            .expect("Failed to attach return uretprobe");
        links.push(uretprobe_link);
    }

    // Set up ring buffer
    let mut builder = libbpf_rs::RingBufferBuilder::new();
    builder
        .add(&skel.maps.span_events, |data| process_span_event(data))
        .expect("Failed to add ringbuf");

    let ringbuf = builder.build().expect("Failed to create ring buffer");

    println!("Listening for span events... Press Ctrl+C to exit.");
    loop {
        if let Err(e) = ringbuf.poll(Duration::from_secs(1)) {
            eprintln!("Error polling ring buffer: {}", e);
        }
    }
}
