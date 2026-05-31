package com.aryan.dpi_engine.dpi.engine;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Thread-safe queue for passing packets between threads.
 * Used for: Reader -> LB -> FP communication.
 */
public class ThreadSafeQueue<T> {
    private final LinkedBlockingQueue<T> queue;
    private final AtomicBoolean shutdown = new AtomicBoolean(false);

    public ThreadSafeQueue(int maxSize) {
        this.queue = new LinkedBlockingQueue<>(maxSize);
    }

    public ThreadSafeQueue() {
        this(10000);
    }

    /** Push item to queue (blocks if full) */
    public void push(T item) {
        if (shutdown.get()) return;
        try {
            queue.put(item);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Try to push without blocking */
    public boolean tryPush(T item) {
        if (shutdown.get()) return false;
        return queue.offer(item);
    }

    /** Pop item from queue (blocks if empty). Returns null on shutdown. */
    public T pop() {
        try {
            while (!shutdown.get()) {
                T item = queue.poll(100, TimeUnit.MILLISECONDS);
                if (item != null) return item;
            }
            // Drain remaining on shutdown
            return queue.poll();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    /** Pop with timeout. Returns null on timeout or shutdown. */
    public T popWithTimeout(long timeoutMs) {
        try {
            return queue.poll(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    /** Check if empty */
    public boolean isEmpty() {
        return queue.isEmpty();
    }

    /** Get current size */
    public int size() {
        return queue.size();
    }

    /** Signal shutdown (wake up all waiting threads) */
    public void shutdown() {
        shutdown.set(true);
    }

    public boolean isShutdown() {
        return shutdown.get();
    }
}
