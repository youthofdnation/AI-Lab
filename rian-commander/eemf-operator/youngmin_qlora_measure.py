"""Child process of youngmin.qlora_probe: can Qwen3-8B QLoRA train on THIS GPU at this size?

No weights are downloaded and no data file is read. The public Qwen3-8B architecture (sizes from
its published config) is built with RANDOM weights: every decoder projection becomes a 4-bit NF4
bitsandbytes layer, embeddings / lm_head / norms are bf16, LoRA adapters go on all seven
projections, and a few optimizer steps run on random token ids. Speed and memory of a step do not
depend on the weight values, so this measures feasibility without touching any RIAN data.

Prints one JSON line. Status: written 2026-11-22, NOT yet executed on a CUDA GPU (no reachable PC had
the CUDA stack installed); the first run is its own test.
"""
import json
import sys
import time


def main():
    p = json.loads(sys.argv[1])
    import torch
    import bitsandbytes as bnb
    from peft import LoraConfig, get_peft_model
    from transformers import Qwen3Config, Qwen3ForCausalLM
    assert torch.cuda.is_available()
    dev, bf16 = torch.device("cuda"), torch.bfloat16
    cfg = Qwen3Config(hidden_size=4096, intermediate_size=12288, num_hidden_layers=36, num_attention_heads=32,
                      num_key_value_heads=8, head_dim=128, vocab_size=151936, max_position_embeddings=40960,
                      rms_norm_eps=1e-6, rope_theta=1000000.0, tie_word_embeddings=False, torch_dtype="bfloat16")
    t0 = time.perf_counter()
    torch.cuda.reset_peak_memory_stats()
    with torch.device("meta"):
        model = Qwen3ForCausalLM(cfg)
    gen = torch.Generator().manual_seed(0)
    for layer in model.model.layers:
        for parent in (layer.self_attn, layer.mlp):
            for name, mod in list(parent.named_children()):
                if isinstance(mod, torch.nn.Linear):
                    q = bnb.nn.Linear4bit(mod.in_features, mod.out_features, bias=False, compute_dtype=bf16, quant_type="nf4")
                    w = (torch.randn(mod.out_features, mod.in_features, generator=gen) * 0.02).to(bf16)
                    q.weight = bnb.nn.Params4bit(w, requires_grad=False, quant_type="nf4")
                    setattr(parent, name, q.to(dev))           # quantised on the move to the GPU
        for norm in (layer.input_layernorm, layer.post_attention_layernorm, layer.self_attn.q_norm, layer.self_attn.k_norm):
            norm.weight = torch.nn.Parameter(torch.ones(norm.weight.shape, dtype=bf16, device=dev), requires_grad=False)
    model.model.embed_tokens = torch.nn.Embedding(cfg.vocab_size, cfg.hidden_size, dtype=bf16, device=dev).requires_grad_(False)
    model.lm_head = torch.nn.Linear(cfg.hidden_size, cfg.vocab_size, bias=False, dtype=bf16, device=dev).requires_grad_(False)
    model.model.norm.weight = torch.nn.Parameter(torch.ones(cfg.hidden_size, dtype=bf16, device=dev), requires_grad=False)
    rot = type(model.model.rotary_emb)
    model.model.rotary_emb = rot(config=cfg, device=dev)
    load_s = time.perf_counter() - t0
    load_peak = torch.cuda.max_memory_allocated() // 2**20
    if p["gradCheckpointing"]:
        model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
        model.enable_input_require_grads()
    model = get_peft_model(model, LoraConfig(r=p["rank"], lora_alpha=2 * p["rank"], lora_dropout=0.0, bias="none",
                                             target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
                                             task_type="CAUSAL_LM"))
    model.to(dev)
    trainable = sum(x.numel() for x in model.parameters() if x.requires_grad)
    opt = torch.optim.AdamW([x for x in model.parameters() if x.requires_grad], lr=1.5e-4)
    model.train()
    step_s = []
    for _ in range(p["steps"]):
        ids = torch.randint(0, cfg.vocab_size, (p["batch"], p["seqLen"]), device=dev)
        torch.cuda.synchronize()
        s = time.perf_counter()
        loss = model(input_ids=ids, labels=ids).loss
        loss.backward()
        opt.step()
        opt.zero_grad(set_to_none=True)
        torch.cuda.synchronize()
        step_s.append(time.perf_counter() - s)
    free, total = torch.cuda.mem_get_info()
    print(json.dumps({"load_seconds": round(load_s, 1), "load_peak_mib": int(load_peak),
                      "train_peak_allocated_mib": int(torch.cuda.max_memory_allocated() // 2**20),
                      "train_peak_reserved_mib": int(torch.cuda.max_memory_reserved() // 2**20),
                      "device_total_mib": int(total // 2**20), "trainable_params": int(trainable),
                      "step_seconds": [round(x, 3) for x in step_s], "tokens_per_step": p["batch"] * p["seqLen"],
                      "gpu": torch.cuda.get_device_name(0), "torch": torch.__version__}))


if __name__ == "__main__":
    main()
